# Auditex Administrator Permission Guide

See [default Exchange and public DNS collection](setup-guide.md#default-exchange-and-public-dns-collection) for app-mode selection, external requests, deselection and failure semantics.

`Exchange.ManageAsApp` is an Office 365 Exchange Online application permission, not Graph. It is write-capable-named and used read-only: read-only Get-* cmdlets only; no mutating cmdlet is issued; the Exchange.ManageAsApp role assignment gives Global Reader only. Its blast radius is tenant-wide Exchange policy visibility under that reader role. Install `pwsh` and `ExchangeOnlineManagement`, grant tenant admin consent to this Exchange permission and assign Global Reader to the service principal before app-mode collection. A write-capable scope does not authorise tenant writes.

This guide tells a tenant administrator what access Auditex needs and why. Auditex is audit-only: requested access is for evidence collection and report generation, not production fixes.

Before granting anything, generate the exact plan for the intended coverage:

```bash
auditex setup-guide m365 --auditor-profile global-reader --collector-preset full --format md
auditex setup-guide google --auth domain-delegation --collector-preset everything --format md
```

Use the generated plan as the admin request. It includes selected collectors, required scopes or Graph permissions, setup steps, verification commands, and read-only assertions.

## Microsoft 365 Access Models

### Local sensitive-user list

For SS 2.1, an authorised operator can name the accounts whose anti-phishing
protection should be assessed. Supply a local file to `auditex run`,
`azure-tenant-audit` or `auditex guided-run` with `--sensitive-users FILE`, or
set `AUDITEX_SENSITIVE_USERS_FILE`. The flag takes precedence. Offline replay
accepts the same input. This needs no extra tenant permission.

Use UTF-8 plain text with one e-mail address per line, or a JSON array of
e-mail strings. `name;email` lines or array strings are accepted; the name is
discarded. Addresses are trimmed, lower-cased, de-duplicated and sorted.
The file must be non-empty, at most 256 KiB and at most 10,000 entries before
de-duplication. Invalid entries reject the whole file before collection; errors
identify the line without displaying personal data.

Auditex opens this file once locally, read-only. The list is never uploaded or
logged. It retains one confidential copy at
`<run-dir>/operator-inputs/sensitive-users.txt` (0600, git-ignored and marked
REDACTED). It is excluded from customer packs, reports,
the evidence index and built-in exports. The manifest's
`operator_inputs.sensitive_users` records only `supplied`, the unique `count`
and `hmac_sha256` of the sorted normalised newline-joined list without a final
newline: HMAC-SHA256 with a per-run 32-byte key held only in
`operator-inputs/sensitive-users.key` (0600); do not share either file.
Both files are excluded from those outputs and listed only by path and the
`redacted_operator_input` exclusion reason in `bundle-hashes.json`, without
hashes or byte lengths. Without input the manifest records `supplied: false`.
Resuming retains the key when the list is supplied again and removes both files
otherwise; support can call
`azure_tenant_audit.sensitive_users.verify_sensitive_users(run_dir)` to check
the private files against the manifest.

SS 2.1 remains not assessed without this operator input. SS 2.3 also remains
not assessed without its operator input, but the v3.9.1 specification calls
that separate input `PartnerDomains`; this file does not supply it. Connecting
the sensitive-user copy to the in-memory `scuba_config` rule view is a separate
product integration; collection alone does not enable the assessment.

### Delegated Read Login

Use this when an operator signs in with a tenant account.

Recommended role:

- Global Reader for broad audit coverage.

Useful narrower roles:

- Security Reader for security posture.
- Reports Reader for usage and report surfaces.
- Exchange admin or Exchange reader tooling only when Exchange command coverage is explicitly in scope.

Command shape:

```bash
auditex setup-guide m365 --mode delegated --auditor-profile global-reader --collector-preset full
az login --allow-no-subscriptions --tenant <tenant-id-or-domain>
auditex probe live --tenant-name CLIENT --tenant-id <tenant-id-or-domain> --mode delegated --use-azure-cli-token
auditex run --tenant-name CLIENT --tenant-id <tenant-id-or-domain> --auditor-profile global-reader --plane full --use-azure-cli-token
```

Expected blockers on basic tenants:

- premium Entra risk APIs may be unavailable,
- Defender or Secure Score may be empty or blocked by license,
- Intune may be absent; Intune answers `Forbidden` both for missing scopes and for an unlicensed tenant, so Auditex reports a licence blocker when `subscribedSkus` (licensing collector) shows no Intune-capable SKU and a scope blocker otherwise,
- user sign-in activity needs `AuditLog.Read.All` and Entra ID P1/P2; without them identity still runs and records a coverage gap instead of stale-account findings,
- audit/sign-in log history may be limited,
- some SharePoint or Exchange depth may need extra role or app-only coverage.

Auditex records these as blockers in `live-readiness.json` and `audit-plan.json`.

### App-Readonly

Use this when a customer grants an app registration for repeatable read-only audits.

Typical Microsoft Graph application permissions depend on selected collectors, but commonly include:

- `Directory.Read.All`
- `User.Read.All`
- `Group.Read.All`
- `RoleManagement.Read.Directory` (also reads the PIM assignment and eligibility schedules, which the administrator set needs)
- `AccessReview.Read.All` and `EntitlementManagement.Read.All` (the rest of the `identity_governance` collector, which the `auto`, `global-reader` and `full` and `config-only` presets now include)
- The PIM role policies of the directory roles (expiration, notification and approval rules, read for the `privileged_roles` evidence) need no scope beyond `RoleManagement.Read.Directory`, which covers them: an existing registration that grants it needs no change and is not asked to consent again. A new registration that wants least privilege for these policy reads may grant `RoleManagementPolicy.Read.Directory` for them (the `identity_governance` schedule reads still need `RoleManagement.Read.Directory`). Auditex does not require `RoleManagementPolicy.Read.Directory`: scope names are compared exactly, so a tenant that granted the existing set is never shown as blocked for want of it. PIM for Groups policies need `RoleManagementPolicy.Read.AzureADGroup` and are not read. Without either scope the policy reads are recorded as `blocked_permission` and named in `collection_gaps`, the `identity_governance` collector reads `partial`, and no `privileged_roles` evidence is written; its other reads are unaffected.
- `Policy.Read.All`
- `AuditLog.Read.All` (also enables user `signInActivity` for stale-account findings, which needs Microsoft Entra ID P1 or P2, and the Graph beta `servicePrincipalSignInActivities` report for dormant-application findings)
- `Reports.Read.All`
- `ReportSettings.Read.All` (reads whether usage reports conceal user, group, and site names)
- `Application.Read.All`
- `DelegatedPermissionGrant.Read.All`
- `SecurityAlert.Read.All` (alerts v2), `SecurityIncident.Read.All`, and `SecurityEvents.Read.All` (Secure Score) where Defender/Security APIs are in scope.
- `DeviceManagementManagedDevices.Read.All`, `DeviceManagementConfiguration.Read.All` and `DeviceManagementApps.Read.All` where Intune is in scope. The device posture fields (encryption, jailbreak, owner type, enrolment, last sync, OS version), the Defender antivirus state of Windows devices (`managedDevices/{id}/windowsProtectionState`, at most 100 devices), the compliance policy assignments and the Windows Update for Business update rings and profiles (the quality and feature update profiles are Graph beta) all use these three scopes: Auditex 1.1 adds no new scope for them. The Intune reports API that returns Defender state for every device at once is a POST export job and is not used, so a larger fleet is reported as a gap in `collection_gaps` (the Defender rules read `not_assessed`; the rest of the Intune evidence is unaffected), not read.
- `IdentityRiskyUser.Read.All` only when the opt-in `identity_protection` collector is selected (Entra ID P2; stores aggregate counts only).
- `ConsentRequest.Read.All` only when the opt-in `defender_cloud_apps` collector (app consent requests) is in scope. Defender for Cloud Apps app risk profiles have no Microsoft Graph REST endpoint; review them in the Defender portal.

Use `auditex probe live --mode app` before full collection. Do not grant broad permissions automatically. Auditex never requests `AppRoleAssignment.ReadWrite.All` (an app holding it can grant itself any permission) or `Mail.Read` (message content); app role assignments are read with `Application.Read.All` and inbox rules with `MailboxSettings.Read`. Some shipped profile hints include `Exchange.ManageAsApp`, which needs an Exchange role assignment and does not by itself establish least privilege. Review the generated plan and the blocked surface with the administrator before approving any broader grant. The audit commands themselves must remain read-only.

### Exchange-Assisted Coverage

Exchange posture can use Microsoft 365 CLI and PowerShell adapters where Graph has poor coverage. Auditex still records the command surface and keeps audit output read-only. Do not use production write commands.

Detection coverage reads `Get-AdminAuditLogConfig`, `Get-OrganizationConfig`, and `Get-MailboxAuditBypassAssociation` in Exchange Online PowerShell, and lists `Get-ProtectionAlert` as requiring Security & Compliance PowerShell. Auditex opens no `Connect-IPPSSession`, so that read remains a coverage gap. These are read-only `Get-*` cmdlets; View-Only Organization Management or Global Reader is sufficient. Without the session the signal is reported as `unknown`, not `off`.

Mail protection reads `Get-MalwareFilterPolicy` (the common attachment types filter and zero-hour auto purge of every policy, the default one and custom ones), `Get-TransportConfig` (`Name`, `SmtpClientAuthenticationDisabled`), `Get-CASMailbox` (only a count of the mailboxes that switch SMTP AUTH back on for themselves; it enumerates every mailbox, which takes longer in a large tenant) and `Get-DkimSigningConfig` (DKIM signing per domain) in the same Exchange Online session. They are read-only `Get-*` cmdlets that pass the shared read guard and need no role beyond Global Reader. Without the session the matching rules read `not_assessed`, never a pass. Defender for Office 365 / EOP reads add preset and built-in protection rules, anti-malware assignments and file types, Safe Attachments policies and rules, anti-phish settings and rules, hosted content filter policies and rules, Safe Links policies and rules, hosted connection filter settings and the SharePoint/Teams/OneDrive ATP policy setting. They use the same Exchange Online session with `Exchange.ManageAsApp` plus Global Reader only, add no Graph scope and remain read-only. Recipient and recipient-group rule scope lists are stored as same-length placeholders; non-empty strings become `"recipient"` and non-empty dictionaries become `["recipient"]`. Nulls and empty values stay unchanged, domain scopes are retained and targeted user lists are not selected. Rule error payloads replace `stdout` with its length in `stdout_bytes` and retain `stderr`; the adapter's audit-log `stdout_sample` is recorded before payload minimisation with e-mail/UPN local parts and dashed GUIDs masked by the shared diagnostic boundary. A licence limit is inferred only when both ATP licence-check reads fail with `command_error` after the adjacent `eopProtectionPolicyRules` read succeeds. Each reclassified envelope retains its error text and carries `licence_inferred: true`; authentication, session and `command_not_found` failures stay coverage gaps. The unlicensed-tenant error text and class remain to be confirmed on the playground tenant.

`Get-OrganizationConfig` selects `Identity`, `Name` and `AuditDisabled`. `Get-TransportRule` retains an explicit field list including `State`, `Mode`, `FromScope` and `PrependSubject`; the latter two are rule configuration and a subject-prefix setting, without reading mail. Full transport-rule objects are never selected, because conditions and exceptions can hold addresses and keywords. `Get-SharingPolicy` selects `Name` and `Domains` (partner domain names and sharing actions), readable with Global Reader, the role ScubaGear's own prerequisites list for this cmdlet. No message content is read.

Public DNS reads need no sign-in: DoH TXT queries cover `<domain>` for SPF, `_dmarc.<domain>` and up to seven parent labels for DMARC, and `selector1._domainkey.<domain>`, `selector2._domainkey.<domain>`, `selector1-<domain with dots as dashes>._domainkey.<domain>` and `selector2-<domain with dots as dashes>._domainkey.<domain>` for DKIM. Complete TXT answers are saved for SPF, DKIM and DMARC for Exchange accepted domains excluding coexistence when complete same-run `acceptedDomains` evidence is available. Otherwise the fallback remains verified domains with the Email service, whose Graph `supportedServices` includes `Email` (a missing or non-list field is kept); posture checks still cover every verified domain. HTTPS reads (MTA-STS and OpenID discovery) stay limited to Graph-verified tenant domains. See the Exchange section below for evidence reuse, limits and coverage metadata.

## Google Workspace Access Models

### Domain-Wide Delegation

Domain-wide delegation is the preferred path for Google Workspace coverage, and the only one that can read each user's own Gmail settings. It uses:

- a Google Cloud service account,
- the service account OAuth client ID,
- an Admin Console domain-wide delegation entry,
- a delegated subject admin such as `admin@example.com`,
- explicit OAuth scopes.

In Google Admin Console:

1. Open Security > Access and data control > API controls > Domain-wide delegation.
2. Add the service account client ID.
3. Paste the comma-separated scopes for the collector preset you intend to run.
4. Save, then probe and record any propagation or authorization failure.

Core scopes:

```text
https://www.googleapis.com/auth/admin.directory.user.readonly,https://www.googleapis.com/auth/admin.directory.group.readonly,https://www.googleapis.com/auth/admin.directory.domain.readonly,https://www.googleapis.com/auth/admin.directory.orgunit.readonly,https://www.googleapis.com/auth/admin.directory.rolemanagement.readonly,https://www.googleapis.com/auth/admin.directory.user.security,https://www.googleapis.com/auth/admin.reports.audit.readonly,https://www.googleapis.com/auth/admin.reports.usage.readonly,https://www.googleapis.com/auth/apps.alerts,https://www.googleapis.com/auth/cloud-identity.policies.readonly,https://www.googleapis.com/auth/gmail.settings.basic,https://www.googleapis.com/auth/gmail.settings.sharing,https://www.googleapis.com/auth/admin.directory.device.mobile.readonly,https://www.googleapis.com/auth/admin.directory.device.chromeos.readonly
```

`cloud-identity.policies.readonly` reads the organisation's 2-step verification policy (Cloud Identity Policy API). Enable the **Cloud Identity API** in the Google Cloud project, and add the scope to the delegation entry. Auditex requests it on its own token, separate from the other scopes, so a tenant that has not added it yet loses only the policy read: the run is partial, `google.collector_issue` names the surface, and the organisation policy is reported as unknown rather than as not enforced.

Everything preset additional scopes:

```text
https://www.googleapis.com/auth/drive.metadata.readonly,https://www.googleapis.com/auth/drive.readonly,https://www.googleapis.com/auth/apps.groups.settings,https://www.googleapis.com/auth/admin.directory.resource.calendar.readonly,https://www.googleapis.com/auth/calendar.calendarlist.readonly,https://www.googleapis.com/auth/calendar.acls.readonly
```

`drive.readonly` is broad. Auditex does not read Drive file content, but Google may require broad scope for some metadata or permission surfaces. The data-handling and API inventory artifacts declare the scope risk and no-content-read claim: `drive.readonly` is listed under `auth_scope_summary.content_capable` and `scope_risk` is `content_capable_scope_present` when no write-capable scope is present.

#### What each collector's evidence covers

Delegation uses one admin subject (`--subject`) for the Directory, Reports, Alert Center and Cloud Identity reads, which are tenant-wide whoever asks. The three collaboration surfaces are per user, and Auditex treats them as follows. Each coverage row, capability row and finding carries a `subject_scoped` label, and the normalized snapshot lists the scope of each collector (`subject_scope`).

| Collector | Subject scope | What the evidence is |
| --- | --- | --- |
| `google_gmail_settings` | `user` with delegation | Each active user's own settings (auto-forwarding, filters, forwarding addresses, send-as, IMAP, POP, vacation, delegates), read by acting as that user. The reads are bounded: 500 mailboxes without `--top`, the `--top` value otherwise. A longer user list records a `mailboxSettingsFanout` coverage gap and the run is partial. Suspended and archived accounts are not read (`mailboxSettingsSkipped` records how many). |
| `google_gmail_settings` | `admin` without delegation | OAuth cannot act as another user, so only the signed-in mailbox is read (`mailboxSettings:me`) and a `mailboxSettingsScope` gap states how many users were not read. |
| `google_drive_posture` | `admin` | Files and shared drives the delegated admin can see. The Admin SDK has no cheap tenant-wide Drive permission read, so this is not a statement about the domain; the Reports `driveActivities` log is the tenant-wide signal. |
| `google_calendar_posture` | `admin` for calendars and ACLs | The admin's calendar list and the ACLs the admin can read. `calendarResources` is a tenant-wide Directory inventory and is not labelled. |

A finding built from `admin`-scoped evidence says so in its description and in `subject_scoped: admin`; do not present it as an organisation-wide result. The per-user token is narrowed to `gmail.settings.basic` and `gmail.settings.sharing`, so the token that can act as any user does not carry the other scopes in the delegation entry. The service account must be allowed to impersonate every user for the Gmail settings; a refused impersonation is a failed `mailboxSettings:<user>` row, and all of them together raise one `google.collector_issue` for the surface with the count of mailboxes.

Probe after adding scopes:

```bash
auditex setup-guide google --auth domain-delegation --collector-preset everything --domain example.com --subject admin@example.com
auditex google probe \
  --auth domain-delegation \
  --service-account-key /path/to/service-account.json \
  --subject admin@example.com \
  --domain example.com \
  --customer-id C123 \
  --collector-preset everything \
  --top 1 \
  --page-size 1
```

### OAuth

OAuth is useful for partial review or development, but some domain-wide APIs may remain blocked. Use OAuth when a service account is not available and label the run as partial when required surfaces are missing.

```bash
auditex google run \
  --auth oauth \
  --oauth-client /path/to/oauth-client.json \
  --token-cache .secrets/google-token.json \
  --domain example.com \
  --tenant-name CLIENT-GOOGLE
```

## Permission Review During Audit

After a run, review:

- `audit-plan.json` for required and missing permissions,
- `live-readiness.json` for trusted and untrusted surfaces,
- `api-inventory.json` for observed calls and scope risk,
- `data-handling.json` for no-write and no-content-read assertions,
- `auditex report permissions <run-dir> --format md` for a reviewer-friendly ledger.

If a run is partial, do not add broad permissions blindly. Add the smallest needed read permission, rerun probe, then rerun the audit only when the new surface is confirmed.

## Local Auth File Handling

- Store service-account files, OAuth client files, token caches, app auth values, and bearer material outside git.
- Prefer `.secrets/` or a local auth folder excluded from source control.
- Do not paste auth values into docs, reports, issue trackers, or customer packs.
- Delete old caches when rotating access.

## Read-Only Rule

If a permission name includes write capability but is required by a provider to read settings, Auditex may record it as scope risk. The audit path must still use only read methods and must not mutate the tenant.

### Exchange Online in app-only runs

Exchange policy, audit, and forwarding checks run read-only `Get-*` cmdlets. In app mode Auditex requests an Exchange Online token for the audit app (`https://outlook.office365.com/.default`) and connects with `Connect-ExchangeOnline -AccessToken` against the tenant's initial `.onmicrosoft.com` domain; the token is passed to PowerShell through an environment variable, never on the command line. This needs the `Exchange.ManageAsApp` application permission on Office 365 Exchange Online plus a read role for the service principal, such as Global Reader ([Microsoft guidance](https://learn.microsoft.com/powershell/exchange/app-only-auth-powershell-v2)). Without them the checks are reported as `session_not_connected` or `command_not_authenticated` coverage gaps. `Get-ProtectionAlert` needs a Security & Compliance PowerShell session, which Auditex does not open, so alert policies stay a coverage gap in app mode; Security & Compliance DLP policy/rule and alert policy reads are not collected.

The same Exchange session reads `Get-SharingPolicy` (`Name`, `Domains`), readable with Global Reader, the role ScubaGear's own prerequisites list for this cmdlet. It uses the existing grants and reads partner-sharing configuration without message content. `Get-OrganizationConfig` includes `Identity`, `Name`, `AuditDisabled`; `Get-TransportConfig` includes `Name`, `SmtpClientAuthenticationDisabled`; `Get-TransportRule` includes `State`, `Mode`, `FromScope`, `PrependSubject` in its explicit configuration field list. The same session reads `Get-AcceptedDomain` with `Name`, `DomainName`, `DomainType`, `Default`, `IsCoexistenceDomain`. Complete same-run accepted-domain evidence supplies the SPF, DKIM and DMARC raw-record universe: domain names de-duplicated case-insensitively with the first-seen spelling retained and coexistence rows excluded. When both collectors are selected, `dns_posture` runs after `exchange_policy` and reuses that evidence without another tenant read or additional grants. Missing, failed, truncated or malformed evidence falls back to verified domains with the Email service; missing or non-list Graph `supportedServices` is kept. Coverage records `domain_universe` as `accepted_domains` or `graph_email_service`. These TXT lookups use public DNS without sign-in, retain the 200-domain record cap and fail-closed behaviour, and leave posture checks over all verified domains unchanged.

## Power Platform and Power BI (optional)

This is extended scope, off by default and available only in the commercial cloud.
With app credentials configured locally, deliberately opt in for a run:

```bash
auditex run --tenant-name CLIENT --tenant-id <tenant-id-or-domain> \
  --collector-preset power-platform --plane inventory
```

For an app-mode probe, explicitly select the surfaces instead:

```bash
auditex probe live --tenant-name CLIENT --tenant-id <tenant-id-or-domain> \
  --mode app --surface identity,licensing,power_platform,power_bi
```

The preset selects `identity`, `licensing`,
`power_platform` and `power_bi`; it does not extend `full` or any existing preset.
Both collector definitions remain `enabled: false`: presets and explicit collector
selection use the configured names, rather than filtering on that flag. To add these
reads to another selection, explicitly name all the desired collectors, including
`identity`, `licensing`, `power_platform` and `power_bi`, with `--collectors`.

The customer carries out the one-time setup below. Auditex never registers an app,
changes a tenant setting, assigns a role or runs the setup commands. No additional
Microsoft Graph application permission is introduced by these collectors; the
supporting organisation and service-plan reads use the existing `Directory.Read.All`.

1. **Power BI service-principal route first:** create a plain Entra security group
   without role assignment and add the customer-owned audit app's service principal.
   In Power BI Admin portal, open Tenant settings > Admin API settings; enable
   **Service principals can access read-only admin APIs** for **Specific security
   groups**, selecting that group. Do not grant any Power BI API permission, and
   never grant `Tenant.Read.All`. The setting permits the group's service principals
   to read tenant-wide admin metadata; keep group membership restricted to the audit
   app. The alternative operator role is Fabric Administrator with a Power BI or
   Fabric licence and at least one prior sign-in to the Power BI portal. It is a
   write-capable admin role used read-only, with tenant-wide Power BI/Fabric
   administrative blast radius. This operator route is a prerequisite reference,
   not a working delegated token path in Auditex.
2. **Power Platform management-app route first:** an authorised customer
   administrator signs in interactively with the Power Apps administration module
   (`Add-PowerAppsAccount -Endpoint prod -TenantID <tenant id>`) and performs the
   one-time registration
   `New-PowerAppManagementApp -ApplicationId <app id>` for the customer-owned audit
   app. This registration is a customer-side write. The upstream prerequisite states
   that its Power Platform permissions **include write privileges**; the management
   app's blast radius is **UNKNOWN** beyond that statement. The alternative operator
   role is Power Platform Administrator with a Power Apps for Office 365 licence.
   It is a write-capable admin role used read-only; it can administer environments
   and policy across the tenant. Auditex itself writes nothing. This operator route
   likewise does not supply a delegated token path in Auditex.

In app mode each collector obtains its own token through `app_token_for`, using
`https://service.powerapps.com//.default` (the double slash is intentional) and
`https://analysis.windows.net/powerbi/api/.default`. Do not supply a separate bearer
token. Configure the app authentication locally using the existing app-mode process.
See the selected collector notes in
`auditex setup-guide m365 --collector-preset power-platform --plane inventory --mode app --format json`.
The JSON guide includes these setup requirements only when the collectors are selected.

Every request is GET only. Power Platform returns environment id/name, SKU, default
status and creation time; environment display names are discarded because developer
and trial environments can be named after people and no rule reads that field. DLP
policy display names remain because the rules read them. Other reads retain DLP
connector counts and environment scope, environment-creation and sharing flags, and
the tenant-isolation disabled flag. Power BI retains tenant setting names, enabled
values and security-group ids, plus a local access-denial observation. Neither
collector reads message bodies or file content. The exact endpoints, API versions
and retained fields are in the [API call catalogue](../reference/api-call-catalog.md#optional-power-platform-and-power-bi).

`listTenantSettings` is a read, pinned to GET with `api-version=2023-06-01` and
`TENANT_SETTINGS_METHOD = "GET"`. A POST is only a possible later fallback if GET is
refused, to be decided after a playground check. No POST or automatic fallback is
currently enabled; whether the live endpoint accepts GET remains unverified.

Without the opt-in, optional Power BI / Power Platform collection was not enabled;
these policies are not assessed: MS.POWERBI 1.1, 2.1, 3.1, 4.1, 4.2, 5.1, 6.1 and
7.1; MS.POWERPLATFORM 1.1, 1.2, 2.1, 2.2, 3.1, 5.1 and 6.1. All 15 also stay not
assessed on delegated runs, even with the roles above, because Auditex has no
delegated token path for either audience. Missing setup, denied reads and incomplete
or truncated evidence also withhold the dependent sections rather than passing them.
MS.POWERPLATFORM.2.3 is a separate constant not-assessed policy and is not enabled by
this opt-in. Missing optional sections on a run with a known collector selection now carry
`optional_collection_not_enabled`; unknown selection and selected-collector failures retain their
existing reasons. The [output contract](../reference/output-contract.md) defines the exact conditions.

Prerequisite reference: ScubaGear revision `2446ad723b7f55031cc02c8aca244d731d468cba`,
`docs/prerequisites/noninteractive.md` (Power BI tenant setting and Power Platform
registration) and `interactive.md` (operator roles, licences and prior portal sign-in).

### Teams policy reads in app-only runs

The Teams policy reader uses certificate authentication for audience `48ac35b8-9aa8-4d74-927d-1f4a14a0b239` (scope `48ac35b8-9aa8-4d74-927d-1f4a14a0b239/.default`) and the read-only **Global Reader** directory role assigned to the audit service principal. It adds no Graph scope or write permission. The reader sends only five allowlisted HTTPS GETs to `api.interfaces.records.teams.microsoft.com`, for meeting policies, federation settings, client configuration, app permission policies and broadcast policies. Only consumed policy fields are stored; the REST mapping omits the unused `AllowIPVideo` and `ScreenSharingMode` fields while PowerShell selects stay unchanged; no message, chat, channel or file content is read. Tokens stay in memory and HTTP authorisation headers, never logs, bundle files or command lines.

Each REST operation caps decoded response bodies at 4 MiB in total across both attempts (including error responses), with a 90-second monotonic deadline covering requests, body reads and its single retry. Oversized responses yield `response_too_large`; an expired deadline yields `timeout`, withholding all rows. At the deadline the reader shuts down an accessible response socket to interrupt a blocked body read; the worker then closes the response. Before response headers arrive, or if the transport exposes no socket, the worker may remain for as long as the peer keeps sending, then up to the 30-second socket inactivity timeout; it holds the token in memory only. Successful responses require `application/json`, UTF-8 (optionally with a UTF-8 BOM), no NUL bytes, an object or non-empty `value` list envelope, all required policy fields with the expected types, and at most 32 JSON container levels scanned and parsed from the same decoded text. Malformed evidence yields `unexpected_shape`; top-level arrays, error envelopes and partial pages are withheld. Empty responses are also withheld for all five operations: the configurations are singletons and each policy family includes Global. The downstream Teams adapters can propagate a complete empty operation as `[]`, so this anomaly must be rejected by the reader. An empty `AllowedDomains` field inside a valid federation row remains legal.

Commercial and GCC are supported; GCC High, DoD and unknown environments are not collected (`unsupported_environment`) and make no Teams admin API call. In supported environments, without a usable certificate token, all seven operations are `skipped` with reason `teams_token_unavailable`, without attempting any `Get-Cs*` command or Teams admin API read. The collector completes `ok`; Teams alone does not make the run partial or return exit code 1. The coverage gaps, report pack and handoff state "not collected: certificate token for the Teams admin API not available" and the policies remain not assessed, never a pass or not applicable. In unsupported environments the five REST operations retain their `unsupported_environment` failures; the two command operations skip without a token. A service refusal with a usable token or a missing role yields `command_not_authenticated`, never a pass. With a usable token, messaging and app setup policies are still skipped as coverage gaps with reason and collector error class `teams_powershell_not_supported` ("not collected: Teams PowerShell sessions are not supported"); no PowerShell command is attempted. Auditex has no Teams PowerShell connection path in any authentication mode.

Certificate authentication is evidenced by ScubaGear at pinned commit `2446ad72`, `Modules/Connection/Connection.psm1` (`Get-MsalAccessToken -CertificateThumbprint` for the Teams scope); its API catalogue specifies Global Reader. The current Auditex CLI resource-token provider supports client secrets only; certificate token acquisition is not implemented by this reader. Until a certificate-capable client supplies a token, ordinary app runs remain behind `teams_token_unavailable`. The reader requires the Teams audience and certificate credential claim (`appidacr` or `azpacr` equal to `2`); the service validates the token itself.

Client-secret token acceptance was **not verified live** (playground check not run) and that credential path is disabled for Teams policy reads. Certificate-authenticated reads and actual REST response shapes have also not been verified live. Org-wide `tenant_app_settings` remain uncollected on app-only runs, so TEAMS 5.1-5.3 remain not assessed; no certificate marker is synthesised to bypass that gap.
