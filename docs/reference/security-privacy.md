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
status, content-read status, and write actions; it is a declaration.
`api-inventory.json` records declared collectors, the collectors' own call
rows, permissions, call classification, and safety counts, and (Microsoft 365)
an `observed_ledger` read back from the run's own `audit-log.jsonl`: the
methods and endpoints the transport actually sent, the commands the adapters
actually ran, and the calls refused. Final audit-plane validation rejects
bundles that report tenant writes or body or file content reads. These
artifacts support review of a run; they do not authorize access or replace an
operator's obligations.

## What is enforced where

Read-only and data minimisation are enforced in code at the layer that makes the
call, and the audit log records both what ran and what was refused.

| Control | Enforced in | What it does | Where it shows |
| --- | --- | --- | --- |
| Microsoft Graph methods | `GraphClient._request` (`graph.py`) | Allows `GET`, and `POST` only to the Graph `/$batch` endpoint when every inner request is a relative `GET` without a body. Anything else raises `GraphError` (`ReadOnlyViolation`) before a token is requested or the network is touched. Every request must be HTTPS to `graph.microsoft.com` (also for `get_json(..., full_url=True)`), so the bearer token cannot go to another host, and `X-HTTP-Method-Override`, `X-HTTP-Method` and `X-Method-Override` headers are refused, on the request and on each `$batch` inner request. The OAuth token endpoint is the only other call the client makes. | `graph.request.refused` event; `observed_ledger.graph.refused` |
| Command adapters | `adapters/read_guard.py`, called by the m365 CLI, PowerShell and Microsoft365DSC adapters before any process starts | Both languages are checked as plain ASCII: any non-ASCII or control character (other than tab, LF, CR) is refused, because the parsers treat Unicode quotes, dashes and line breaks differently from this check; a CR ends a statement like an LF. m365: the executable must be `m365`, the command must end in `list`, `get` or `status` (or be an `outlook report <name>` usage report), and after the command words every token must be a known option (`--output`/`-o`, `--period`, `--top`, `--help`/`-h`, `--verbose`, `--debug`) or that option's value, so a later bare word or `--` cannot extend the command inside the CLI parser. PowerShell: only `Get-*`, a few read-shaping pipeline cmdlets and `Search-UnifiedAuditLog`; comments, backticks, redirection, here-strings, `::`, a call operator on anything but a script block, subexpressions in double-quoted strings, dynamic member access (`.` followed by a quote or `$`) and method calls other than a few string helpers are refused. Microsoft365DSC also allows `Export-M365DSCConfiguration`, which reads the tenant and writes only local files. The lab response plane runs through the same adapters, so `--command-override` is held to the same allowlist. It is a syntactic allowlist that fails closed, not a PowerShell parser; the read-only role and scopes remain the authoritative boundary. Refusal reasons are redacted and clipped before they are logged. | `command.refused` event; `observed_ledger.commands.refused` |
| API ledger | `api_inventory.py`, attached by `AuditWriter.write_json_artifact` to every `api-inventory.json` it writes | `safety.read_only` and `safety.no_content_reads` are re-derived from the audit log. A write method, a non-read command, any refused call, a `$batch` whose inner calls or methods were not all recorded, a malformed or unreadable log line, a body-reading endpoint or a `$select` of a body field makes them false, whatever the collectors declared. Logged command words are cross-checked against the logged command text. Observed calls outside the declared set are listed. | `api-inventory.json` `observed_ledger`, `safety.observation_basis` |
| Bundle files | `output.py` (`AuditWriter`, `harden_bundle`), `evidence_db.py` | Run directories and every directory under them are `0700`; every file is `0600`; the audit log, evidence database and temporary files are created that way, whatever the caller's umask. A final sweep covers files other code wrote into the bundle. Symbolic links are left alone. | `ls -l` of the bundle |
| User-authored text | `data_minimisation.py`, used by `google_workspace/client.py`, `google_workspace/collectors.py`, `collectors/mailbox_forwarding.py`, both normalizers, `AuditWriter` and the offline replay copy in `cli.py` | Gmail vacation-responder subject and body (plain and HTML), Gmail send-as signatures and Graph automatic-reply message bodies are dropped before `raw/`, `normalized/`, `ai_safe/`, chunk files or any report, on live collection and on offline replay of a fixture. The booleans (`enableAutoReply`, `restrictToDomain`, `status`, `externalAudience`) and a `<field>Length` and `has<Field>` pair per dropped field stay. | `raw/`, `normalized/` |
| MCP tools | `mcp_registry.py`, `mcp_paths.py`, `mcp_server.py` | No tool takes a bearer token or client secret: auth comes from the local auth context and the server's environment (`AZURE_CLIENT_SECRET`). Every filesystem argument is resolved against the MCP root and refused when it contains `..`, starts with `~`, or lands outside the root (including through a symbolic link). Tenant and run names (which become part of a run directory name) are refused when they contain `/`, `\`, `..` or a control character; `AuditWriter` enforces the same rule. The server refuses to start, and every path argument is refused, when the root is `/`, or the home directory with `AUDITEX_MCP_ROOT` unset. Read-only annotations are unchanged. | `McpPathError` from the tool |

The MCP root is `AUDITEX_MCP_ROOT` when set, otherwise the server's working
directory. Run outputs, run directories, credential file paths and imported
assessment files must sit under it. The shipped defaults for `config_path`,
`schema_dir` and `sample_path` pass unchanged; any other value is confined. The
`auditex_setup_guide` path arguments are rendered into guide text and are never
opened.

Not enforced by these layers: Google Workspace SDK calls are not routed through
a method check and write no per-call audit events, so Google bundles say
`observation_basis: "coverage_ledger_only"` and rely on read-only scopes and the
collectors' use of list and get methods; the `dns_posture`, exposure and `power_platform`
lookups use their own GET-only sessions rather than `GraphClient`, and the
`probe` toolchain checks that start `pwsh` or `az` directly are outside the
adapters; `command.completed` events keep a 500-character redacted sample of
command output. The effective boundary against a mistake in any of these is the
read-only role and scopes granted to the auditor.

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

Bearer tokens are imported and inspected only through the local CLI
(`auditex auth ...`); the MCP server has no tool that accepts one.

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
