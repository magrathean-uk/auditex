# Auditex API Call Catalog

Auditex writes `api-inventory.json` into every finalized bundle. This artifact is the customer-facing ledger for what the tool attempted to read, which collector attempted it, which permission family was needed, and whether any content or write action occurred.

## Contract

`api-inventory.json` contains:

- `declared_collectors`: planned collector coverage, status, required permissions, observed permissions, and missing permissions.
- `observed_calls`: the declared call rows: endpoint-level calls the collectors recorded in their coverage rows (and, for command rows, the command text). This is the expected set, not proof of what was sent.
- `observed_ledger`: what was sent, read back from the run's own `audit-log.jsonl` (see below).
- `counts`: declared collector count, declared call count, mutating call count, content-read call count, beta call count (`beta_calls`), and from the observed ledger `observed_graph_requests`, `observed_graph_endpoints`, `observed_commands`, `refused_calls` and `observed_outside_declared`.
- `safety`: read-only status, no-content-read status, write-capable scopes, any mutating/content-read exceptions, and from the observed ledger `observation_basis`, `observed_methods`, `observed_write_calls`, `observed_content_read_calls`, `refused_calls` and `observed_outside_declared`.

## Observed ledger

`AuditWriter` builds `observed_ledger` from the `graph.request.*`, `graph.token.*` and `command.*` events in `audit-log.jsonl` every time it writes `api-inventory.json`, so a caller cannot write the ledger from declarations alone. The declared rows above stay as the expected set the observed calls are compared with.

```
observed_ledger
  source, basis ("transport_audit_log" or "not_instrumented"), instrumentation
  graph
    request_attempts, methods_seen (HTTP methods on the wire, e.g. GET and POST),
    data_methods_seen (after unpacking $batch: GET only in a read-only run),
    batch_requests, batch_inner_requests, unverified_batch_requests,
    endpoints[]  method, endpoint (ids templated as {id}), api_version, count, statuses
    write_calls[], content_read_calls[], refused[], refused_count
  commands
    executed[]   adapter, command (the command words), family, read_only, count, statuses
    write_calls[], refused[], refused_count
  log            readable, malformed_lines
  auth           token_requests, token_succeeded, token_failed
  outside_declared  graph[], commands[], count
```

How `safety` is derived: `read_only` is false when any non-`GET` data call was observed, any executed command is not a read, any call was refused (`refused_calls`), or the log cannot be fully read: a `$batch` request whose inner calls, inner methods or call count were not all recorded (`unverified_batch_requests`), a malformed line (`malformed_log_lines`, counted and never silently skipped) or a log that could not be opened. `observed_log_complete` says whether everything in the log could be read and verified. `no_content_reads` is false when an observed endpoint reads content (messages, attachments, `/content`, `/$value`, calendar events, OneNote, `/search/query`) or a `$select` asks for `body`, `bodyPreview`, `uniqueBody` or `content`. Microsoft service-health posts (`/admin/serviceAnnouncement/messages`) are not user content. A refused call is counted in `refused_calls` and makes `read_only` false, because the run tried something that is not a read; it is not a write (`write_actions` stays as observed), because nothing reached the tenant. A call outside the declared set is listed in `outside_declared` for review and does not by itself change `read_only`.

Commands are classified from the command words each adapter recorded, using the same read rules the adapters enforce, so a log written by a build that did not enforce them is still flagged. The words are cross-checked against the logged command text: an m365 command's words must equal the words before its first option, and a PowerShell command's text must contain no cmdlet-shaped token outside the read allowlist and must contain every recorded word. A disagreement is treated as not read-only. Older events without recorded words are classified from the logged text.

`observation_basis` says what the safety flags rest on. Microsoft 365 bundles say `transport_audit_log`. Google Workspace bundles say `coverage_ledger_only`: the Google API client is not instrumented, so for those the flags rest on the collectors' declared rows and the read-only scopes. A run with no Graph traffic (offline, sample) records zero requests, which is an observed fact for the Microsoft 365 transport.

Token requests to the OAuth endpoint are counted under `auth`, not under `graph`. Collectors that start local tools outside the adapters (the `probe` toolchain checks, `dns_posture` lookups) are not in this ledger.

## Removed command variants

The Purview collector no longer tries these `m365` commands. They were guesses at CLI spellings, not reads the CLI documents, and the first three are not read commands at all, so they fail the shared read allowlist:

| Removed | Collector operation | Why |
| --- | --- | --- |
| `m365 purview audit-log search` | `auditLogJobs` | A search submits an audit-log query job on the tenant. |
| `m365 purview auditlog search` | `auditLogJobs` | Same. |
| `m365 purview auditlog export create` (probed with `--help`) | `auditLogExports` | Creates an export; only ever probed with `--help`. |
| `m365 purview` | `purviewReadiness` | A bare command-group probe that prints help and reads nothing. |

`auditLogJobs` and `auditLogExports` now run only `m365 purview auditlog list` (the latter with `--top 100`), and `purviewReadiness` runs only `m365 purview auditlog list --output json --help`. The read-only spelling variants (`retentionlabel list` and `retention label list`, and so on) stay.

Each observed Graph call records `api_version` (`v1.0` or `beta`). Auditex calls Microsoft Graph v1.0 by default. A collector endpoint uses beta only when the surface has no v1.0 equivalent, and the call then shows the full `https://graph.microsoft.com/beta/...` endpoint with `api_version: "beta"`. Current beta reads:

| Collector | Endpoint | Permission | Notes |
| --- | --- | --- | --- |
| `intune_depth` | `/deviceManagement/groupPolicyConfigurations` | `DeviceManagementConfiguration.Read.All` | Not available on v1.0. |
| `intune_depth` | `/deviceManagement/deviceManagementScripts` | `DeviceManagementConfiguration.Read.All` | Fixed `$select` of metadata fields; `scriptContent` (the script body) is never requested. |
| `app_credentials` | `/reports/servicePrincipalSignInActivities` | `AuditLog.Read.All` | Capability-gated; without it `app_credentials.credential_dormant` is not evaluated. |

Other v1.0 reads with gating worth knowing:

- `identity` reads `/users?$select=id,signInActivity` as a separate query (page size at most 500; `AuditLog.Read.All` plus Microsoft Entra ID P1 or P2). A licence or scope failure leaves a coverage gap and identity continues.
- Identity relationship expansion reads complete collected group and
  role-assignment evidence, including chunk rows, and expands at most 50
  distinct privileged or nested groups. Coverage records input completeness,
  expanded groups and remaining discovered groups.
- App-consent relationship expansion covers the first ten collected service
  principals plus Microsoft Graph wherever it appears within the collected
  inventory. Coverage reports selected and omitted principals, collection
  limits and unreadable evidence. Invalid chunk inputs retain raw evidence and
  produce a coverage gap. Derived fan-out summaries are coverage observations,
  not additional API calls.
- `directory_relationships` is opt-in and reads security-group inventories,
  `GET /groups/{id}/members`, `GET /groups/{id}/owners`, application inventories
  and `GET /applications/{id}/owners`. Permissions are `Directory.Read.All`,
  `Group.Read.All`, and `Application.Read.All`. It expands at most 100 groups
  and 100 applications; `--top` limits each inventory and relationship (5000
  relationship rows maximum for unbounded runs). Each failed or capped read
  has a coverage row. Application registration ownership and enterprise-app
  service-principal ownership remain distinct observations.
- `conditional_access` reads `GET /policies/identitySecurityDefaultsEnforcementPolicy` (`Policy.Read.All`) beside the Conditional Access policies it already reads. It is a single object with an `isEnabled` flag; Auditex needs it because a tenant on security defaults has no Conditional Access policies yet still requires MFA. Together with `/identity/conditionalAccess/policies` (full conditions: user, group and role include and exclude lists, applications, `clientAppTypes`, grant controls and authentication strength) it feeds the `effective_mfa` and `legacy_authentication_block` verdicts. No new permission is needed.
- `auth_methods` reads `/reports/authenticationMethods/userRegistrationDetails` with a fixed `$select` of metadata fields: `id`, `userPrincipalName`, `userType`, `isAdmin`, `isMfaCapable`, `isMfaRegistered`, `isPasswordlessCapable`, `isSsprEnabled`. `userType` and `isAdmin` let the MFA registration rules tell privileged and guest accounts from ordinary members. No authentication method values are requested.
- `consent_policy` already reads `/policies/authorizationPolicy`; normalization now keeps `defaultUserRolePermissions.permissionGrantPoliciesAssigned`, `allowedToCreateApps` and `guestUserRoleId` for the `user_consent` verdict. No new call.
- `reports_usage` reads `/admin/reportSettings` (`ReportSettings.Read.All`) before the usage reports. When `displayConcealedNames` is true, per-user report rows are hashed and Auditex raises `reports_usage.concealed_names`.
- `defender_cloud_apps` reads only `/identityGovernance/appConsent/appConsentRequests` (`ConsentRequest.Read.All`). Microsoft Graph has no documented endpoint for Defender for Cloud Apps app risk profiles.

Declared collector access metadata comes from the same shipped scope catalog used by `auditex setup-guide`, so reviewer-facing permission rows and operator-facing setup rows stay aligned.

The bundle validator fails audit-plane bundles when this artifact reports tenant writes or body/file content reads. Because the observed ledger feeds those flags, a write method, a non-read command or a body-reading endpoint seen in the audit log fails validation even when a collector declared a clean run.

## Read-Only Rules

Auditex 1.0 audit paths are read-only:

- No Gmail body reads.
- No Drive file content reads.
- No Exchange mailbox body reads.
- No SharePoint or OneDrive file content reads.
- No Graph or Google tenant writes from audit, probe, report, export, or MCP audit tools.

Some providers expose settings through broad scopes. When that happens, `data-handling.json` and `api-inventory.json` both record the scope risk and the fact that Auditex used read methods only.

## Detection Coverage And Public Lookups

These reads feed `report_pack["detection_coverage"]` and `report_pack["public_footprint"]`. All are read-only.

| Collector | Call | Purpose | Reference |
| --- | --- | --- | --- |
| `exchange_policy` | `Get-AdminAuditLogConfig` (Exchange Online PowerShell) | `UnifiedAuditLogIngestionEnabled` | <https://learn.microsoft.com/en-us/purview/audit-log-enable-disable> |
| `exchange_policy` | `Get-OrganizationConfig` | `AuditDisabled` (mailbox auditing on by default) | <https://learn.microsoft.com/en-us/purview/audit-mailboxes> |
| `exchange_policy` | `Get-MailboxAuditBypassAssociation` | Count of accounts with `AuditBypassEnabled`; names are not kept | <https://learn.microsoft.com/en-us/powershell/module/exchangepowershell/get-mailboxauditbypassassociation> |
| `exchange_policy` | `Get-ProtectionAlert` (Security & Compliance PowerShell only) | Alert policy name, state, severity, category | <https://learn.microsoft.com/en-us/powershell/module/exchangepowershell/get-protectionalert> |
| `identity_protection` (opt-in) | `GET /identityProtection/riskyUsers` (one page, `$select=id,riskLevel,riskState`) | Whether Identity Protection risk detection exists; counts only | <https://learn.microsoft.com/en-us/graph/api/riskyuser-list?view=graph-rest-1.0> |
| `conditional_access`, `security`, `defender`, `sentinel_xdr` | existing reads | Risk-based policies, sign-in and directory audit availability, alerts API reachability | see collector definitions |
| `dns_posture` | DoH `TXT _smtp._tls.<domain>` | TLS-RPT record (RFC 8460) | <https://datatracker.ietf.org/doc/html/rfc8460> |
| `dns_posture` | `GET https://mta-sts.<domain>/.well-known/mta-sts.txt` | MTA-STS policy mode, only when `_mta-sts` TXT exists; no redirects, 64 KiB cap | <https://learn.microsoft.com/en-us/exchange/security-and-compliance/enhance-mail-flow-using-strict-transport-security> |
| `dns_posture` | `GET https://login.microsoftonline.com/<domain>/v2.0/.well-known/openid-configuration` | Public tenant ID, region scope, cloud instance | <https://learn.microsoft.com/en-us/entra/identity-platform/v2-protocols-oidc> |

Public HTTPS lookups target only domains that Microsoft Graph reports as verified for the audited tenant (at most 25). They are unauthenticated, never probe usernames, and do not use `getuserrealm.srf`. Offline runs make none of these calls. Entra diagnostic-settings export (Azure Resource Manager `microsoft.aadiam/diagnosticSettings`) is not collected, so the `siem_log_export` signal is always `unknown`.

## Customer Use

For enterprise review, create and verify a customer pack, inspect it for confidential data, and use the approved evidence channel. Keep raw evidence local unless separately authorized for disclosure. Review these artifacts first:

1. `run-manifest.json`
2. `data-handling.json`
3. `api-inventory.json`
4. `audit-plan.json`
5. `live-readiness.json`
6. `reports/report-pack.json` (`proof_table` maps findings to exact evidence rows)
7. `validation.json`

These files show what was planned, what was called, what was blocked, what was proven, and what limitations remain.

For command-line handoff:

```bash
auditex report customer-pack <run-dir> --output-dir customer-pack
auditex report verify-pack customer-pack
auditex report handoff <run-dir> --format md
auditex report api-calls <run-dir> --format md
auditex report permissions <run-dir> --format md
auditex report proof-table <run-dir> --format md
```

Add `--output <path>` to persist individual review files outside the verified pack. Regenerate and reverify the pack when its contents need to change.

The permission ledger joins `api-inventory.json` and `audit-plan.json` so reviewers can see required, observed, and missing scopes per collector. The `customer-pack` command also copies selected customer-safe source artifacts, including `data-handling.json`, `api-inventory.json`, `audit-plan.json`, `reports/report-pack.json`, `validation.json`, and `ai_context.json`, under `source-artifacts/` with hashes in `pack-manifest.json` and `checksums.sha256`. Run `verify-pack` before handoff.
