# Auditex API Call Catalog

Auditex writes `api-inventory.json` into every finalized bundle. This artifact is the customer-facing ledger for what the tool attempted to read, which collector attempted it, which permission family was needed, and whether any content or write action occurred.

## Contract

`api-inventory.json` contains:

- `declared_collectors`: planned collector coverage, status, required permissions, observed permissions, and missing permissions.
- `observed_calls`: the declared call rows: endpoint-level calls the collectors recorded in their coverage rows (and, for command rows, the command text). This is the expected set, not proof of what was sent.
- `observed_ledger`: what was sent, read back from the run's own `audit-log.jsonl` (see below).
- `counts`: declared collector count, declared call count, mutating call count, content-read call count, beta call count (`beta_calls`), and from the observed ledger `observed_graph_requests`, `observed_graph_endpoints`, `observed_teams_admin_rest_requests`, `observed_teams_admin_rest_endpoints`, `observed_commands`, `refused_calls` and `observed_outside_declared`.
- `safety`: read-only status, no-content-read status, write-capable scopes, any mutating/content-read exceptions, and from the observed ledger `observation_basis`, `observed_methods`, `observed_write_calls`, `observed_content_read_calls`, `refused_calls` and `observed_outside_declared`.

## Observed ledger

`AuditWriter` builds `observed_ledger` from the `graph.request.*`, `graph.token.*`, `teams_admin_rest.request`, `sharepoint_admin_rest.*` and `command.*` events in `audit-log.jsonl` every time it writes `api-inventory.json`, so a caller cannot write the ledger from declarations alone. The declared rows above stay as the expected set the observed calls are compared with.

```
observed_ledger
  source, basis ("transport_audit_log" or "not_instrumented"), instrumentation (graph, teams_admin_rest, commands, google_api)
  graph
    request_attempts, methods_seen (HTTP methods on the wire, e.g. GET and POST),
    data_methods_seen (after unpacking $batch: GET only in a read-only run),
    batch_requests, batch_inner_requests, unverified_batch_requests,
    endpoints[]  method, endpoint (ids templated as {id}), api_version, count, statuses
    write_calls[], content_read_calls[], refused[], refused_count
  teams_admin_rest
    request_attempts, methods_seen
    endpoints[]  method, host, path, endpoint, count, statuses
    write_calls[]  method, endpoint (non-GET, or UNVERIFIED for a missing method)
  sharepoint_admin_rest
    request_attempts, methods_seen
    endpoints[]  method, host ({tenant}-admin.sharepoint.com), path, endpoint, count, statuses
    write_calls[]  method, endpoint (non-GET, or UNVERIFIED for a missing method)
    refused[], refused_count  (requests the read guard refused before sending; they count into refused_calls)
  commands
    executed[]   adapter, command (the command words), family, read_only, count, statuses
    write_calls[], refused[], refused_count
  log            readable, malformed_lines
  auth           token_requests, token_succeeded, token_failed
  outside_declared  graph[], teams_admin_rest[], sharepoint_admin_rest[], commands[], count
```

`auth` counts every app-token exchange with the Entra token endpoint. With a certificate credential each exchange is an msal client-credentials grant signed with the key; its `graph.token.*` events carry `mode: certificate`, the token endpoint and the scope (and a plain OAuth error code on failure), never the assertion, the key, its password, the thumbprint or a token.

How `safety` is derived: `read_only` is false when any non-`GET` data call was observed, any executed command is not a read, any call was refused (`refused_calls`), or the log cannot be fully read: a `$batch` request whose inner calls, inner methods or call count were not all recorded (`unverified_batch_requests`), a malformed line (`malformed_log_lines`, counted and never silently skipped) or a log that could not be opened. `observed_log_complete` says whether everything in the log could be read and verified. `no_content_reads` is false when an observed endpoint reads content (messages, attachments, `/content`, `/$value`, calendar events, OneNote, `/search/query`) or a `$select` asks for `body`, `bodyPreview`, `uniqueBody` or `content`. Microsoft service-health posts (`/admin/serviceAnnouncement/messages`) are not user content. A refused call is counted in `refused_calls` and makes `read_only` false, because the run tried something that is not a read; it is not a write (`write_actions` stays as observed), because nothing reached the tenant. A call outside the declared set is listed in `outside_declared` for review and does not by itself change `read_only`.

Commands are classified from the command words each adapter recorded, using the same read rules the adapters enforce, so a log written by a build that did not enforce them is still flagged. The words are cross-checked against the logged command text: an m365 command's words must equal the words before its first option, and a PowerShell command's text must contain no cmdlet-shaped token outside the read allowlist and must contain every recorded word. A disagreement is treated as not read-only. Older events without recorded words are classified from the logged text.

`observation_basis` says what the safety flags rest on. Microsoft 365 bundles say `transport_audit_log`. Google Workspace bundles say `coverage_ledger_only`: the Google API client is not instrumented, so for those the flags rest on the collectors' declared rows and the read-only scopes. A run with no Graph traffic (offline, sample) records zero requests, which is an observed fact for the Microsoft 365 transport.

Endpoint templates replace only identifiers with `{id}` (a GUID, a segment with `@`, an all-digit segment, or an opaque identifier of 24 or more characters that contains a digit or `_`, `=` or `-`); a long letters-only segment such as `deviceCompliancePolicies` is a resource name and stays, so an undeclared sibling endpoint is listed under `outside_declared`. The declared command set includes every spelling in a row's `command_variants`; the eDiscovery rows carry all the spellings the collector may try. `graph.redirects` lists the redirect hops `GraphClient` followed (host and path only; the usage-report functions answer 302 to a pre-authenticated download URL fetched without the bearer token) and `graph.redirects_refused` counts those it refused. Mailbox forwarding is read with `Get-EXOMailbox -ResultSize 501 -Properties ForwardingSmtpAddress,ForwardingAddress,DeliverToMailboxAndForward -Filter 'ForwardingSmtpAddress -ne $null -or ForwardingAddress -ne $null'`, so the answer does not depend on tenant size.

Token requests to the OAuth endpoint (for Graph and for another resource such as Exchange Online) are counted under `auth`, not under `graph`. Collectors that start local tools outside the adapters (the `probe` toolchain checks, `dns_posture` lookups) are not in this ledger.

## Removed command variants

Live collection does not start the Microsoft 365 CLI at all (the `exchange` collector records the named skip `m365_cli_not_used`). The Purview collector once tried these `m365` commands, and the ledger still classifies them in logs of earlier runs. They were guesses at CLI spellings, not reads the CLI documents, and the first three are not read commands at all, so they fail the shared read allowlist:

| Removed | Collector operation | Why |
| --- | --- | --- |
| `m365 purview audit-log search` | `auditLogJobs` | A search submits an audit-log query job on the tenant. |
| `m365 purview auditlog search` | `auditLogJobs` | Same. |
| `m365 purview auditlog export create` (probed with `--help`) | `auditLogExports` | Creates an export; only ever probed with `--help`. |
| `m365 purview` | `purviewReadiness` | A bare command-group probe that prints help and reads nothing. |

Before the CLI was dropped, `auditLogJobs` and `auditLogExports` ran only `m365 purview auditlog list` (the latter with `--top 100`), and `purviewReadiness` ran only `m365 purview auditlog list --output json --help`; the read-only spelling variants (`retentionlabel list` and `retention label list`, and so on) were kept.

Each observed Graph call records `api_version` (`v1.0` or `beta`). Auditex calls Microsoft Graph v1.0 by default. A collector endpoint uses beta only when the surface has no v1.0 equivalent, and the call then shows the full `https://graph.microsoft.com/beta/...` endpoint with `api_version: "beta"`. Current beta reads:

| Collector | Endpoint | Permission | Notes |
| --- | --- | --- | --- |
| `intune_depth` | `/deviceManagement/groupPolicyConfigurations` | `DeviceManagementConfiguration.Read.All` | Not available on v1.0. |
| `intune_depth` | `/deviceManagement/deviceManagementScripts` | `DeviceManagementScripts.Read.All` | Fixed `$select` of metadata fields; `scriptContent` (the script body) is never requested. |
| `intune_depth` | `/deviceManagement/windowsQualityUpdateProfiles` | `DeviceManagementConfiguration.Read.All` | Not available on v1.0. Windows quality (expedite) update profiles. |
| `intune_depth` | `/deviceManagement/windowsFeatureUpdateProfiles` | `DeviceManagementConfiguration.Read.All` | Not available on v1.0. Windows feature update profiles. |
| `intune_depth` | `/deviceManagement/windowsQualityUpdateProfiles/{id}/assignments`, `/deviceManagement/windowsFeatureUpdateProfiles/{id}/assignments` | `DeviceManagementConfiguration.Read.All` | One GET per profile, at most 100 profiles. Beta reads are not batched because `$batch` here targets v1.0. |
| `consent_policy` | `/settings` | `Directory.Read.All` | Inline directory-setting groups; only `EnableAdminConsentRequests` values survive minimisation. Beta for parity with ScubaGear's `Get-MgBetaDirectorySetting`; v1.0 `/groupSettings` not yet shown to return the consent settings group. |
| `app_credentials` | `/reports/servicePrincipalSignInActivities` | `AuditLog.Read.All` | Capability-gated; without it `app_credentials.credential_dormant` is not evaluated. |

The SharePoint and OneDrive reads are Microsoft Graph v1.0:

| Collector | Endpoint | Permission | Notes |
| --- | --- | --- | --- |
| `sharepoint`, `sharepoint_access`, `onedrive_posture` | `/admin/sharepoint/settings` | `SharePointTenantSettings.Read.All` | SharePoint and OneDrive tenant settings; a single GET. |
| `sharepoint`, `sharepoint_access`, `onedrive_posture` | `/sites` | `Sites.Read.All` | Fixed `$select` of site metadata; no file or list content. |
| `sharepoint_access` | `/sites/{id}/permissions` | `Sites.Read.All` | Not read: in an app-only run the endpoint lists app grants, not user sharing, so the collector records a named skip. |

Other v1.0 reads with gating worth knowing:

- `intune` reads `/deviceManagement/managedDevices` with a fixed `$select` that adds `isEncrypted`, `jailBroken`, `managedDeviceOwnerType`, `enrolledDateTime` and `deviceEnrollmentType` to the fields it already read (`lastSyncDateTime`, `complianceState`, `osVersion`, `operatingSystem`). `managedDeviceOwnerType` is the v1.0 name; `ownerType` exists on beta only and is not selected. No user principal name, e-mail address, phone number or serial number is selected. No new permission.
- `intune` reads the assignments of every device compliance policy (`GET /deviceManagement/deviceCompliancePolicies/{id}/assignments`, `DeviceManagementConfiguration.Read.All`, through `$batch` with GET-only inner requests, at most 100 policies) and the Defender antivirus state of each Windows managed device (`GET /deviceManagement/managedDevices/{id}/windowsProtectionState`, `DeviceManagementManagedDevices.Read.All`, at most 100 devices). A device Intune has no state for (HTTP 404) is recorded as `not_reported`; any other failure is a failed read. Only a fixed list of state fields is kept (antivirus, real-time protection, signature and scan state, product status, tamper protection, engine and signature versions, last report time). The Intune reports API that returns this for every device at once (`reports/getDefenderAgentsReport`, `reports/exportJobs`) is a POST export job, so the audit plane does not use it. A list longer than the limit is a `fanout_limit` gap in `collection_gaps`, never a complete read; the gap is scoped to the Defender section, so the `intune` collector stays `ok` when its device and policy lists were read in full and only the Defender rules read `not_assessed`.
- `intune_depth` identifies Windows Update for Business update rings from the `deviceConfigurations` list it already reads (the `windowsUpdateForBusinessConfiguration` type, v1.0, no further call), keeps a fixed list of their settings, and reads each ring's assignments with `GET /deviceManagement/deviceConfigurations/{id}/assignments` (at most 100 rings). The quality and feature update profiles are Graph beta (table above).
- `identity_governance` reads `GET /roleManagement/directory/roleAssignmentScheduleInstances` (v1.0, `RoleManagement.Read.Directory`, which the collector already requires; paged, no new scope), the active schedule instances ScubaGear's exporter reads for the privileged roles' assignments. `normalized/privileged_roles.json` takes its `Assignments` from these rows: an assignment made outside PIM has a null `startDateTime` here, while `roleAssignmentSchedules` (still read, for the effective admin set) gives it the read time.
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
- `identity.domains` reads `GET /domains` (v1.0, `Directory.Read.All`), adding `passwordValidityPeriodInDays` to the existing metadata `$select`; the list stays inline and uses the operator row limit without `$top`.
- `auth_methods.authenticationMethodConfigurations` is taken from the inline `authenticationMethodConfigurations` array of `GET /policies/authenticationMethodsPolicy` (v1.0, `Policy.Read.All`); the separate list endpoint is not called. Whole typed policy configurations, no per-user method values.
- `consent_policy.directorySettings` reads `GET /settings` (**beta**, `Directory.Read.All`), inline and paged without `$top`, subject to the operator row limit. Before returning evidence it keeps only group `id`, `displayName`, `templateId` and `values` entries named `EnableAdminConsentRequests`; groups with no matching value stay with `values: []`. Other settings values never reach a chunk writer or the returned payload.
- `consent_policy.defaultAppManagementPolicy` reads `GET /policies/defaultAppManagementPolicy` (v1.0, `Policy.Read.All`); one whole policy object, no `$select` or `$top`.
- `consent_policy.appManagementPolicies` reads `GET /policies/appManagementPolicies` (v1.0, `Policy.Read.All`); whole custom policies, inline and paged without `$top`, subject to the operator row limit. An empty list is legal.
- `consent_policy.appManagementPolicyAppliesTo` reads `GET /policies/appManagementPolicies/{id}/appliesTo?$select=id&$top=50` (v1.0, `Policy.Read.All`); at most 100 policies and the first 50 target IDs per policy. Extra rows or a next-page link set `appliesToTruncated`; caps and failures produce coverage gaps, and a failed policy has no derived row.
- `app_consent.delegatedPermissionClassifications` resolves `GET /servicePrincipals` (v1.0, `Application.Read.All`) with a fixed OR `$filter` of exactly eight `RISKY_RESOURCE_APP_IDS` and `$select=id,appId,displayName`; this lookup is independent of the sampled service-principal inventory and operator row limit. A resource absent from the tenant is legal.
- `app_consent.delegatedPermissionClassifications` then reads `GET /servicePrincipals/{id}/delegatedPermissionClassifications?$select=id,permissionId,permissionName,classification` (v1.0, `Application.Read.All`), paged for at most eight resolved resources. All classifications are retained without risk filtering; a failed resource has no derived row and leaves a coverage gap. New fan-outs use GET directly, without `$batch`.
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
| `exchange_policy` | `Get-AdminAuditLogConfig` (Exchange Online PowerShell) | `Identity`, `UnifiedAuditLogIngestionEnabled` | <https://learn.microsoft.com/en-us/purview/audit-log-enable-disable> |
| `exchange_policy` | `Get-OrganizationConfig` | `Identity`, `Name`, `AuditDisabled` (mailbox auditing on by default) | <https://learn.microsoft.com/en-us/purview/audit-mailboxes> |
| `exchange_policy` | `Get-MailboxAuditBypassAssociation` | Count of accounts with `AuditBypassEnabled`; names are not kept | <https://learn.microsoft.com/en-us/powershell/module/exchangepowershell/get-mailboxauditbypassassociation> |
| `exchange_policy` | `Get-ProtectionAlert` (Security & Compliance PowerShell, app-only certificate runs only) | Alert policy name, state, severity, category; SCuBA MS.SECURITYSUITE.4.1v1 | <https://learn.microsoft.com/en-us/powershell/module/exchangepowershell/get-protectionalert> |
| `exchange_policy` | `Get-Command Get-DlpCompliancePolicy -ErrorAction SilentlyContinue \| Measure-Object \| Select-Object Count` (same session) | Count only: whether the session offers the DLP cmdlets (the DLP licence fact); 0 skips the two DLP reads as `dlp_licence_not_detected` | <https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/get-command> |
| `exchange_policy` | `Get-DlpCompliancePolicy` (same session) | `Name`, `Enabled`, `Mode`, `Workload` and the five location lists cast to text (`ExchangeLocation`, `SharePointLocation`, `OneDriveLocation`, `TeamsLocation`, `EndpointDlpLocation`; entries other than `All` stored as `location`); SS 3.1-3.4 | <https://learn.microsoft.com/en-us/powershell/module/exchangepowershell/get-dlpcompliancepolicy> |
| `exchange_policy` | `Get-DlpComplianceRule` (same session) | `Name`, `ParentPolicyName`, `Disabled`, `IsAdvancedRule`, `AdvancedRule`, `ContentContainsSensitiveInformation`, `BlockAccess`, `BlockAccessScope`, `NotifyUser` (same-length `recipient` placeholders), `NotifyUserType`; SS 3.1-3.4 | <https://learn.microsoft.com/en-us/powershell/module/exchangepowershell/get-dlpcompliancerule> |
| `identity_protection` (opt-in) | `GET /identityProtection/riskyUsers` (one page, `$select=id,riskLevel,riskState`) | Whether Identity Protection risk detection exists; counts only | <https://learn.microsoft.com/en-us/graph/api/riskyuser-list?view=graph-rest-1.0> |
| `conditional_access`, `security`, `defender`, `sentinel_xdr` | existing reads | Risk-based policies, sign-in and directory audit availability, alerts API reachability | see collector definitions |
| `dns_posture` | DoH `TXT <domain>` (Exchange accepted domains excluding coexistence; fallback: verified domains with the Email service) | Complete SPF TXT answers, public DNS without sign-in | Public DNS |
| `dns_posture` | DoH `TXT _dmarc.<domain>` and up to seven parent labels (Exchange accepted domains excluding coexistence; fallback: verified domains with the Email service) | Complete DMARC TXT answers, public DNS without sign-in | Public DNS |
| `dns_posture` | DoH `TXT selector1._domainkey.<domain>`, `selector2._domainkey.<domain>`, `selector1-<domain with dots as dashes>._domainkey.<domain>`, `selector2-<domain with dots as dashes>._domainkey.<domain>` | Complete DKIM TXT answers for the same accepted-domain universe or Graph fallback, public DNS without sign-in | Public DNS |
| `dns_posture` | DoH `TXT _smtp._tls.<domain>` | TLS-RPT record (RFC 8460) | <https://datatracker.ietf.org/doc/html/rfc8460> |
| `dns_posture` | `GET https://mta-sts.<domain>/.well-known/mta-sts.txt` | MTA-STS policy mode, only when `_mta-sts` TXT exists; no redirects, 64 KiB cap | <https://learn.microsoft.com/en-us/exchange/security-and-compliance/enhance-mail-flow-using-strict-transport-security> |
| `dns_posture` | `GET https://login.microsoftonline.com/<domain>/v2.0/.well-known/openid-configuration` | Public tenant ID, region scope, cloud instance | <https://learn.microsoft.com/en-us/entra/identity-platform/v2-protocols-oidc> |

The four Security & Compliance reads run only in an app-only certificate run: each PowerShell process first connects with
`Connect-IPPSSession -AccessToken` (a certificate token for `https://ps.compliance.protection.outlook.com/.default`, the
Microsoft Exchange Online Protection resource; `Exchange.ManageAsApp` on that resource plus Global Reader;
`ExchangeOnlineManagement` 3.8.0 or later) against the initial domain. Every other run, and a connect that fails, records
the section-scoped gap `ipps_session_not_opened` on each of the four reads and invokes none of them after the failure.

SPF, DKIM and DMARC raw-record collection uses complete `exchange_policy.acceptedDomains` evidence from the same run when available: `DomainName` values de-duplicated case-insensitively with the first-seen spelling retained, excluding rows with `IsCoexistenceDomain=true`. When both collectors are selected, the runner delays `dns_posture` until `exchange_policy` finishes; it adds no collector or tenant read. Missing, failed, truncated or malformed accepted-domain evidence (including old rows without the coexistence flag) falls back to verified domains with the Email service; an absent or non-list `supportedServices` field is kept exactly as before. Each raw-record coverage row records `domain_universe` as `accepted_domains` or `graph_email_service`. The 200-domain cap, truncation and fail-closed resolver and Graph failure handling are unchanged. Posture checks still cover every verified domain.

Public HTTPS lookups target only domains that Microsoft Graph reports as verified for the audited tenant (at most 25). They are unauthenticated, never probe usernames, and do not use `getuserrealm.srf`. Offline runs make none of these calls. Entra diagnostic-settings export (Azure Resource Manager `microsoft.aadiam/diagnosticSettings`) is not collected, so the `siem_log_export` signal is always `unknown`.

## Device, Update And Mail Protection Reads

These reads feed the Cyber Essentials update and malware rules (see
[framework mappings](framework-mappings.md#device-update-and-mail-protection-rules)). All are GET requests or read-only
`Get-*` cmdlets that pass the shared read guard. No new Graph scope is needed: each read uses a permission the
collector already required. Exchange cmdlets run in the Exchange Online PowerShell session the other `exchange_policy`
cmdlets use, with the Global Reader role.

| Collector | Call | Purpose | Permission or role |
| --- | --- | --- | --- |
| `intune` | `GET /deviceManagement/managedDevices` (added `$select` fields) | Encryption, jailbreak, owner type, enrolment, last sync, OS version | `DeviceManagementManagedDevices.Read.All` |
| `intune` | `GET /deviceManagement/deviceCompliancePolicies/{id}/assignments` | Whether each compliance policy applies to anybody | `DeviceManagementConfiguration.Read.All` |
| `intune` | `GET /deviceManagement/managedDevices/{id}/windowsProtectionState` | Defender antivirus, real-time protection and signature state per Windows device | `DeviceManagementManagedDevices.Read.All` |
| `intune_depth` | `GET /deviceManagement/deviceConfigurations/{id}/assignments` (update rings only) | Whether each update ring is assigned | `DeviceManagementConfiguration.Read.All` |
| `intune_depth` | `GET /beta/deviceManagement/windowsQualityUpdateProfiles`, `windowsFeatureUpdateProfiles` and their `/{id}/assignments` | Update profiles and their assignments | `DeviceManagementConfiguration.Read.All` |
| `exchange_policy` | `Get-MalwareFilterPolicy` | `Identity`, `Name`, `IsDefault`, `EnableFileFilter`, `ZapEnabled`, `FileTypes` of each anti-malware policy | Exchange Online, Global Reader |
| `exchange_policy` | `Get-TransportConfig` | `Name`, `SmtpClientAuthenticationDisabled` | Exchange Online, Global Reader |
| `exchange_policy` | `Get-CASMailbox -ResultSize Unlimited \| Where-Object { $_.SmtpClientAuthenticationDisabled -eq $false } \| Measure-Object \| Select-Object Count` | Count of mailboxes that switch SMTP AUTH back on (no address is kept) | Exchange Online, Global Reader |
| `exchange_policy` | `Get-AcceptedDomain` | `Name`, `DomainName`, `DomainType`, `Default`, `IsCoexistenceDomain`; also supplies the same-run DNS raw-record universe | Exchange Online, Global Reader |
| `exchange_policy` | `Get-DkimSigningConfig` | `Domain`, `Enabled`, `Status` per domain | Exchange Online, Global Reader |
| `exchange_policy` | `Get-TransportRule` | `Name`, `State`, `Priority`, `Mode`, `RedirectMessageTo`, `BlindCopyTo`, `CopyTo`, `FromScope`, `PrependSubject` | Exchange Online, Global Reader |
| `exchange_policy` | `Get-SharingPolicy` | `Name`, `Domains` (partner domain names and sharing actions) | Exchange Online; readable with Global Reader, the role ScubaGear's own prerequisites list for this cmdlet |
| `exchange_policy` | `Get-EOPProtectionPolicyRule` | `Identity`, `State`, `SentTo`, `SentToMemberOf`, `RecipientDomainIs`, `ExceptIfSentTo`, `ExceptIfSentToMemberOf`, `ExceptIfRecipientDomainIs` | Exchange Online, Global Reader |
| `exchange_policy` | `Get-ATPProtectionPolicyRule` | `Identity`, `State`, `SentTo`, `SentToMemberOf`, `RecipientDomainIs`, `ExceptIfSentTo`, `ExceptIfSentToMemberOf`, `ExceptIfRecipientDomainIs` | Exchange Online, Global Reader |
| `exchange_policy` | `Get-ATPBuiltInProtectionRule` | `Identity`, `ExceptIfSentTo`, `ExceptIfSentToMemberOf`, `ExceptIfRecipientDomainIs` | Exchange Online, Global Reader |
| `exchange_policy` | `Get-AtpPolicyForO365` | `Identity`, `EnableATPForSPOTeamsODB` | Exchange Online, Global Reader |
| `exchange_policy` | `Get-MalwareFilterRule` | `Identity`, `State`, `Priority`, `MalwareFilterPolicy`, `SentTo`, `SentToMemberOf`, `RecipientDomainIs`, `ExceptIfSentTo`, `ExceptIfSentToMemberOf`, `ExceptIfRecipientDomainIs` | Exchange Online, Global Reader |
| `exchange_policy` | `Get-SafeAttachmentPolicy` | `Identity`, `Action` | Exchange Online, Global Reader |
| `exchange_policy` | `Get-SafeAttachmentRule` | `Identity`, `State`, `Priority`, `SafeAttachmentPolicy`, `SentTo`, `SentToMemberOf`, `RecipientDomainIs`, `ExceptIfSentTo`, `ExceptIfSentToMemberOf`, `ExceptIfRecipientDomainIs` | Exchange Online, Global Reader |
| `exchange_policy` | `Get-AntiPhishPolicy` | `Identity`, `Name`, `IsDefault`, `Enabled`, `EnableTargetedUserProtection`, `TargetedUserProtectionAction`, `TargetedUsersToProtect` (transient; see below), `EnableOrganizationDomainsProtection`, `TargetedDomainProtectionAction`, `EnableTargetedDomainsProtection`, `TargetedDomainsToProtect`, `EnableFirstContactSafetyTips`, `EnableSimilarUsersSafetyTips`, `EnableSimilarDomainsSafetyTips`, `EnableUnusualCharactersSafetyTips`, `EnableViaTag`, `EnableUnauthenticatedSender` | Exchange Online, Global Reader |
| `exchange_policy` | `Get-AntiPhishRule` | `Identity`, `State`, `AntiPhishPolicy`, `SentTo`, `SentToMemberOf`, `RecipientDomainIs`, `ExceptIfSentTo`, `ExceptIfSentToMemberOf`, `ExceptIfRecipientDomainIs` | Exchange Online, Global Reader |
| `exchange_policy` | `Get-HostedContentFilterPolicy` | `Identity`, `IsDefault`, `RecommendedPolicyType`, `SpamAction`, `HighConfidenceSpamAction`, `PhishSpamAction`, `HighConfidencePhishAction`, `AllowedSenderDomains` | Exchange Online, Global Reader |
| `exchange_policy` | `Get-HostedContentFilterRule` | `Identity`, `State`, `HostedContentFilterPolicy`, `SentTo`, `SentToMemberOf`, `RecipientDomainIs`, `ExceptIfSentTo`, `ExceptIfSentToMemberOf`, `ExceptIfRecipientDomainIs` | Exchange Online, Global Reader |
| `exchange_policy` | `Get-SafeLinksPolicy` | `Identity`, `EnableSafeLinksForEmail`, `EnableSafeLinksForTeams`, `EnableSafeLinksForOffice`, `EnableForInternalSenders`, `ScanUrls`, `DeliverMessageAfterScan`, `TrackClicks` | Exchange Online, Global Reader |
| `exchange_policy` | `Get-SafeLinksRule` | `Identity`, `State`, `Priority`, `SafeLinksPolicy`, `SentTo`, `SentToMemberOf`, `RecipientDomainIs`, `ExceptIfSentTo`, `ExceptIfSentToMemberOf`, `ExceptIfRecipientDomainIs` | Exchange Online, Global Reader |
| `exchange_policy` | `Get-HostedConnectionFilterPolicy` | `Name`, `IPAllowList`, `EnableSafeList` | Exchange Online, Global Reader |

Transport-rule `FromScope` and `PrependSubject` are configuration (the latter a subject-prefix setting), without reading mail. The `Select-Object` field lists stay explicit; full transport-rule objects can contain addresses and keywords in conditions and exceptions. Sharing-policy reads collect no message content and use the existing Exchange grants.

These Exchange Online reads use `Exchange.ManageAsApp` plus Global Reader only in app mode; no new Graph scope or role is needed. Rule recipient and recipient-group scope lists are stored as same-length `"recipient"` placeholders. Non-empty recipient strings become `"recipient"` and non-empty dictionaries become `["recipient"]`; nulls and empty values stay unchanged, and domain scopes are retained. Rule error payloads retain `stderr` and replace `stdout` with its length in `stdout_bytes`. The adapter's audit-log `stdout_sample` is recorded before payload minimisation with e-mail/UPN local parts and dashed GUIDs masked by the shared diagnostic boundary.

`Get-AntiPhishPolicy` selects `TargetedUsersToProtect` for SCuBA MS.SECURITYSUITE.2.1v1 only; it is the same single read through the same Exchange Online session, with no new cmdlet, permission, Graph read, recipient enumeration or write. The target list (names, addresses, domains, malformed or nested values) stays in process memory. The PowerShell adapter recognises this command as sensitive by itself: it reads stdout in bounded chunks and stops at 64 MiB in total, killing and reaping the child (the operation then fails with `error: command_output_over_limit`, `state: over_limit`), and before any event or return it rebuilds each policy row from the other selected fields plus a `TargetedUsersCoverage` v1 summary. Unknown row fields are not kept; a scalar or otherwise unrepresentable row fails the operation as `command_parse_error` with no row kept. For this command no `stdout_sample`, `stdout`, `stderr` or exception text is recorded on success, warning or failure; events and error payloads carry only the command, fixed error classes, the return code, the duration and byte counts.

The summary is `known` (`input_count`, `input_hmac_sha256`, `protected_nonempty`, `missing_count`) only when the run has a verified non-empty `--sensitive-users` list; its count and HMAC are the writer's `operator_inputs.sensitive_users` values for that run, and the private key never leaves the writer. Without that input it is `not_collected`; an absent, null or non-list field, or any non-string member, is `unusable`; more than 10,000 entries or 262,144 bytes of compact UTF-8 JSON is `over_limit`, never a trimmed prefix. Offline replay applies the same boundary to the sample in memory before `raw/sample_input.json` is written (a supplied summary without literal targets becomes `not_collected`; target fields in other layouts are discarded). `--resume-from` carries `exchange_policy` only when every summary is bound to the resumed session's list and key; otherwise the collector is read again, or, when this session does not select it, its other evidence is kept with every summary `not_collected`. Summaries and the operator count/HMAC are local evidence only.

What could not be collected read-only: the Intune reports API for Defender state (a POST export job), the Windows
Defender settings of a Windows compliance policy (not returned by Graph v1.0), compliance policies built from
settings-catalog templates (not listed by `deviceCompliancePolicies`), the edition of a Windows device (not in
`osVersion`) and enrolment in the Windows 10 Extended Security Updates programme. Each is reported as unknown or
not assessed, never as a pass.

## Teams Policy Reads

A certificate-authenticated Teams admin API token and Global Reader on the service principal enable the five GET paths below, in commercial and GCC only. No new Graph scope is required. The token comes from the run's certificate credential (`--certificate-path` with `--certificate-thumbprint`), minted through `msal.ConfidentialClientApplication` as a client-credentials grant against the tenant's Entra token endpoint; a client secret never mints it. In supported environments, without a usable certificate token, all eight operations are recorded as `skipped` with reason `teams_token_unavailable`; no `Get-Cs*` command or Teams admin API read is attempted. The collector completes `ok`, so Teams alone does not make the run partial or return exit code 1. Coverage gaps, the report pack and handoff say "not collected: certificate token for the Teams admin API not available"; the policies remain not assessed. GCC High and DoD retain `unsupported_environment` failures for the five REST operations and make no Teams admin API call; their two command operations skip without a token, and the unified app-settings read records `unsupported_environment`. With a usable token, messaging and app setup are still skipped with reason `teams_powershell_not_supported` because no Teams PowerShell session path exists. The org-wide unified app settings (`tenantAppSettings`, the source of `Get-M365UnifiedTenantSettings`) are served only to a user sign-in, so an app-only run records the same named skip and sends no request and no token for them; the `tenant_app_settings` rule input is then ScubaGear's certificate-authentication marker (`CertificateBasedAuth: true`), and MS.TEAMS 5.1-5.3 are decided from the app permission policies, as ScubaGear decides them with certificate authentication. A tenant that manages apps only through the newer org-wide app settings in the Teams admin center can read differently there. These REST reads are not verified live. Policy settings only, no messages, chats, channel posts or files.

| Collector | Command | Fields read | Role |
| --- | --- | --- | --- |
| `teams_policy` | `Get-CsTenantFederationConfiguration` | `Identity`, `AllowFederatedUsers`, `AllowTeamsConsumer`, `AllowTeamsConsumerInbound`, `AllowPublicUsers`, `AllowedDomains`, `BlockedDomains` | Global Reader on the service principal; certificate auth; `GET /Skype.Policy/configurations/TenantFederationSettings` |
| `teams_policy` | `Get-CsTeamsMeetingPolicy` | `Identity`, `AllowCloudRecording`, `AllowIPVideo` (PowerShell path only), `ScreenSharingMode` (PowerShell path only), `AllowExternalParticipantGiveRequestControl`, `AllowAnonymousUsersToStartMeeting`, `AutoAdmittedUsers`, `AllowPSTNUsersToBypassLobby` | Global Reader on the service principal; certificate auth; `GET /Skype.Policy/configurations/TeamsMeetingPolicy` |
| `teams_policy` | `Get-CsTeamsAppPermissionPolicy` | `Identity`, `DefaultCatalogAppsType`, `GlobalCatalogAppsType`, `PrivateCatalogAppsType` | Global Reader on the service principal; certificate auth; `GET /Skype.Policy/configurations/TeamsAppPermissionPolicy` |
| `teams_policy` | `Get-CsTeamsMeetingBroadcastPolicy` | `Identity`, `BroadcastRecordingMode` | Global Reader on the service principal; certificate auth; `GET /Skype.Policy/configurations/TeamsMeetingBroadcastPolicy` |
| `teams_policy` | `Get-CsTeamsClientConfiguration` | `Identity`, `AllowEmailIntoChannel` | Global Reader on the service principal; certificate auth; `GET /Skype.Policy/configurations/TeamsClientConfiguration` |
| `teams_policy` | `Get-M365UnifiedTenantSettings` (`tenantAppSettings`) | `SettingName`, `SettingValue` (`Users` and `Groups` are dropped) | Served only to a user sign-in; never sent (named skip `teams_powershell_not_supported`). Pinned read: `GET https://substrate.office.com/AdminAppCatalog/ps/v2/admin/unifiedApp/settings` with a token for resource `08ff1ce2-4973-4b08-86a3-ebed13badc7f`, commercial and GCC only (source: ScubaGear `PowerShell/ScubaGear/schemas/ScubaGearApiCatalog.json`, entries `Get-TeamsM365UnifiedTenantSettingsRest` and `Get-TeamsUnifiedApiEndpoint`; Microsoft Learn `Get-M365UnifiedTenantSettings`). The adapter sends only a token for that audience, never the Teams admin or Graph token |

## SharePoint Admin Settings (opt-in)

The `sharepoint_admin` collector is off by default and in no profile or preset; `--collectors sharepoint_admin` selects
it. It closes MS.SHAREPOINT 1.2, 2.1, 2.2, 3.1, 3.2 and 3.3, whose settings Graph does not carry. The route and the host
rule are pinned from ScubaGear's API catalogue (`PowerShell/ScubaGear/schemas/ScubaGearApiCatalog.json`, entries
`Get-SharePointAdminApiEndpoint` and `Get-SPOTenantRest`); the permissions from Microsoft Learn, "SharePoint admin APIs
authentication and authorization". The
[permission guide](../guides/admin-permission-guide.md#sharepoint-admin-settings-opt-in) describes the write-capable
permission, its blast radius and its removal.

| Collector | Call | Retained fields | Permission or role |
| --- | --- | --- | --- |
| `sharepoint_admin` | `GET /sites/root?$select=siteCollection` (Microsoft Graph) | Nothing is stored; the root site's `siteCollection.hostname` (`<prefix>.sharepoint.com`, the current host after any SharePoint rename) gives the admin host prefix, else the named skip `sharepoint_admin_host_unresolved` | `Sites.Read.All` (read-only, already in the default set) |
| `sharepoint_admin` | `GET https://{tenant}-admin.sharepoint.com/_api/SPO.Tenant` (`Accept: application/json;odata=verbose`, no body, no query, redirects not followed) | `ODBSharingCapability`, `DefaultSharingLinkType`, `DefaultLinkPermission`, `RequireAnonymousLinksExpireInDays`, `FileAnonymousLinkType`, `FolderAnonymousLinkType`, `EmailAttestationRequired`, `EmailAttestationReAuthDays`; everything else in the answer is discarded | App-only: SharePoint `Sites.FullControl.All` with a certificate (a secret run records `sharepoint_admin_certificate_required`). Delegated: SharePoint `AllSites.FullControl`, minted silently from the run's one sign-in, else `sharepoint_admin_second_sign_in_required`. Both write-capable; Auditex sends only this GET |

The read guard (`check_sharepoint_admin_request`) refuses any other verb, host, path, query, header or body before the
request is sent, and the coverage row and the `sharepoint_admin_rest.*` audit events name the host as
`{tenant}-admin.sharepoint.com` (the token events name the token scope, as for every resource).

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

## Optional Power Platform and Power BI

Commercial cloud only; deliberately select the `power-platform` preset. These
collectors add no Graph permission and obtain their own app-mode tokens:
`https://service.powerapps.com//.default` and
`https://analysis.windows.net/powerbi/api/.default`. The
[permission guide](../guides/admin-permission-guide.md#power-platform-and-power-bi-optional)
describes the customer-side setup and write-capable administrative blast radius.

| Collector | Call | Retained fields | Permission or role |
| --- | --- | --- | --- |
| `power_platform` | `GET https://api.bap.microsoft.com/providers/Microsoft.BusinessAppPlatform/scopes/admin/environments?api-version=2023-06-01` | `id`, `name`, `environment_sku` from `environmentSku`, `is_default` from `isDefault` verbatim, `created_time` from `createdTime`; environment `displayName` discarded | Customer's one-time `New-PowerAppManagementApp -ApplicationId <app id>` registration; operator alternative Power Platform Administrator with Power Apps licence (no delegated token path) |
| `power_platform` | `GET https://api.bap.microsoft.com/providers/PowerPlatform.Governance/v2/policies?api-version=2020-10-01` | `id` from `name` or `id`, `display_name` from `displayName`, `environment_type` from `environmentType`; business, non-business and blocked connector counts only | Same Power Platform management-app registration |
| `power_platform` | `GET https://api.bap.microsoft.com/providers/Microsoft.BusinessAppPlatform/scopes/admin/apiPolicies?api-version=2016-11-01` | `name`, `displayName`, derived `environmentType` and `environments: [{name}]` from `properties.definition.constraints.environmentFilter1`; absent and unusable values retained as such | Same Power Platform management-app registration |
| `power_platform` | `POST (no body) https://api.bap.microsoft.com/providers/Microsoft.BusinessAppPlatform/listTenantSettings?api-version=2020-10-01` | `tenantSettings`: `is_power_apps_enabled`, `is_power_automate_enabled`, `is_dataverse_enabled`; `environmentCreation`: present keys `disableEnvironmentCreationByNonAdminUsers`, `disableTrialEnvironmentCreationByNonAdminUsers`, `disablePortalsCreationByNonAdminUsers`, nested `powerPlatform.powerApps.disableShareWithEveryone`; no whole raw settings object | Same Power Platform management-app registration; one read produces two operations |
| `power_platform` | `GET https://api.bap.microsoft.com/providers/PowerPlatform.Governance/v1/tenants/{TenantId}/tenantIsolationPolicy?api-version=2020-06-01` | `properties.isDisabled` verbatim, or `never_configured: true` for empty/null response; the unconfirmed null sentinel withholds rule evidence | Same Power Platform management-app registration; canonical tenant GUID from Graph organisation |
| `power_bi` | `GET https://api.powerbi.com/v1/admin/tenantsettings` | `settingName`, `enabled`, `enabledSecurityGroups` restricted to `graphId` for object entries; local `accessState`: `denied`, `http_status`; titles, group names and other properties discarded | Specific security group containing the app allowed by **Service principals can access read-only admin APIs**; no Power BI API permission, never `Tenant.Read.All`; Fabric Administrator operator alternative requires a licence and prior portal sign-in (no delegated token path) |
| `power_platform`, `identity` | `GET /organization` (Microsoft Graph) | Canonical organisation `id` for isolation and `tenant_id`; existing identity collection unchanged | Existing `Directory.Read.All` |
| `licensing` | `GET /subscribedSkus` (Microsoft Graph) | Existing SKU/service-plan inventory; rule view uses successful `servicePlanName` values to derive `powerbi_license_found` | Existing `Directory.Read.All` |

`listTenantSettings` is a read that Microsoft documents as a body-free POST; `TENANT_SETTINGS_METHOD`
is POST and the client admits POST for that one path only. Live acceptance is not yet verified.
A Power Platform management-app registration makes the app equivalent to a Power Platform
Administrator inside Power Platform (read and write; Microsoft Learn); remove it with
`Remove-PowerAppManagementApp -ApplicationId <app id>` when the audit is done.
