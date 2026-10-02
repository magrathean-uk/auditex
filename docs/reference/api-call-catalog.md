# Auditex API Call Catalog

Auditex writes `api-inventory.json` into every finalized bundle. This artifact is the customer-facing ledger for what the tool attempted to read, which collector attempted it, which permission family was needed, and whether any content or write action occurred.

## Contract

`api-inventory.json` contains:

- `declared_collectors`: planned collector coverage, status, required permissions, observed permissions, and missing permissions.
- `observed_calls`: endpoint-level calls observed during live runs and probes.
- `counts`: declared collector count, observed call count, mutating call count, content-read call count, and beta call count (`beta_calls`).
- `safety`: read-only status, no-content-read status, write-capable scopes, and any mutating/content-read exceptions.

Each observed Graph call records `api_version` (`v1.0` or `beta`). Auditex calls Microsoft Graph v1.0 by default. A collector endpoint uses beta only when the surface has no v1.0 equivalent, and the call then shows the full `https://graph.microsoft.com/beta/...` endpoint with `api_version: "beta"`. Current beta reads:

| Collector | Endpoint | Permission | Notes |
| --- | --- | --- | --- |
| `intune_depth` | `/deviceManagement/groupPolicyConfigurations` | `DeviceManagementConfiguration.Read.All` | Not available on v1.0. |
| `intune_depth` | `/deviceManagement/deviceManagementScripts` | `DeviceManagementConfiguration.Read.All` | Fixed `$select` of metadata fields; `scriptContent` (the script body) is never requested. |
| `app_credentials` | `/reports/servicePrincipalSignInActivities` | `AuditLog.Read.All` | Capability-gated; without it `app_credentials.credential_dormant` is not evaluated. |

Other v1.0 reads with gating worth knowing:

- `identity` reads `/users?$select=id,signInActivity` as a separate query (page size at most 500; `AuditLog.Read.All` plus Microsoft Entra ID P1 or P2). A licence or scope failure leaves a coverage gap and identity continues.
- `reports_usage` reads `/admin/reportSettings` (`ReportSettings.Read.All`) before the usage reports. When `displayConcealedNames` is true, per-user report rows are hashed and Auditex raises `reports_usage.concealed_names`.
- `defender_cloud_apps` reads only `/identityGovernance/appConsent/appConsentRequests` (`ConsentRequest.Read.All`). Microsoft Graph has no documented endpoint for Defender for Cloud Apps app risk profiles.

Declared collector access metadata comes from the same shipped scope catalog used by `auditex setup-guide`, so reviewer-facing permission rows and operator-facing setup rows stay aligned.

The bundle validator fails audit-plane bundles when this artifact reports tenant writes or body/file content reads.

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
