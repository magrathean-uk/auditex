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
de-duplication. Invalid entries reject the whole file before collection. Parser
errors show a fixed message; direct validation can identify the line without
displaying personal data.

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
The count and HMAC stay in the local manifest; shareable reports, exports,
explainer outputs and customer packs retain at most boolean `supplied`.
Resuming retains the key when the list is supplied again and removes both files
otherwise; support can call
`azure_tenant_audit.sensitive_users.verify_sensitive_users(run_dir)` to check
the private files against the manifest.

SS 2.1 remains not assessed without a verified sensitive-user list. A verified
list reaches its private in-memory rule view; a decision also needs usable
policy evidence. The collector reads protected-user targets transiently and
replaces them with a bound summary before saving evidence or diagnostics.
Usable membership can establish met when all other rule conditions hold.
Unknown or over-limit membership stays unusable. Missing verified private
input gives `section_not_collected`; `config_list_empty` describes only a
direct ScubaGear configuration with no usable SensitiveUsers entries.
Changing or clearing the list on resume invalidates old membership reuse.
SS 2.3 uses the separate
`PartnerDomains` input in its own private rule view, independently of
SensitiveUsers. Neither input enters projected views or prompts.

### Local partner domains for SS 2.3

Use `--partner-domains FILE` on `auditex run`, `azure-tenant-audit` or
`auditex guided-run`, or set `AUDITEX_PARTNER_DOMAINS_FILE`; the flag wins.
Offline replay accepts it too. This local input needs no additional tenant
permission. Domains are not personal data but are customer-confidential.

Supply a regular UTF-8 file (optional initial BOM), one bare domain per line or
a JSON array of strings, at most 256 KiB and 10,000 entries. Blank text lines
are ignored; comments and `name;domain` are rejected. Entries are trimmed,
lower-cased, stripped of one trailing dot, sorted and de-duplicated. Use ASCII
DNS names with at least one dot, labels 1-63 characters and total length at most
253; no leading or trailing hyphen, and the last label cannot be all digits or
`0x` followed by hexadecimal digits.
Non-ASCII input is rejected; ASCII punycode is accepted. Do not use e-mail
addresses, URLs, `@` prefixes or wildcards.
Explicit subdomains are literal domains; SS 2.3 v3.9.1 matches exact strings.
Parser errors show a fixed message; direct validation can identify the line.
Neither exposes entries or the source path.

Only `<run-dir>/operator-inputs/partner-domains.txt` persists the normalised list
(0600 in a 0700 directory). A **separate** per-run 32-byte raw HMAC key is kept in
`operator-inputs/partner-domains.key` (0600), never reused from sensitive users.
Do not share either file. The manifest field `operator_inputs.partner_domains`
holds only `supplied` and, when supplied, unique `count` and `hmac_sha256`.
No list is uploaded or included in logs, evidence, AI context, reports, exports
or customer packs; the source path is redacted from command arguments. Demos
ignore the operator environment. Assessment uses the verified snapshot only in
SS 2.3's private in-memory rule view.

Resume replaces this input while keeping its key; omit the input to clear its
list and key. The sibling input is preserved. An existing HMAC with an unusable
key stops the run. Support can use
`azure_tenant_audit.partner_domains.verify_partner_domains(run_dir)` locally;
it checks consistency with the private files, not authenticity against someone
able to rewrite them. The manifest schema defines this field; the output contract
describes its constraints.

### Sign-ins per run and per set-up step

Every service token a run uses comes from one credential or one sign-in: an audit run asks for at
most one interactive sign-in, and none in app-only mode. Auditex never opens a second sign-in window during a
run: when the one sign-in can no longer be refreshed silently the run stops with an error, and a service the
sign-in cannot serve silently (no consent for it) is recorded as a named coverage gap.

| Run mode | Interactive sign-ins per run | Service tokens |
|---|---|---|
| App-only, certificate (`--certificate-path`, `--certificate-thumbprint`) | 0 | All minted silently from the certificate: Microsoft Graph, Exchange Online, Security & Compliance (`exchange_policy` alert and DLP reads), the Teams admin API, Power BI and Power Platform |
| App-only, client secret (`--client-secret`) | 0 | Minted silently from the secret: Microsoft Graph, Exchange Online, Power BI and Power Platform; the Teams admin policies (`teams_token_unavailable`) and the Security & Compliance reads (`ipps_session_not_opened`) are skipped, never prompted |
| Guided `app-audit` with Exchange | 0 | As app-only; the Microsoft 365 CLI signs in with the client secret, without a browser |
| Delegated, one sign-in (`--interactive --client-id <sign-in app>`, and guided `gr-audit` when the sign-in app id is saved or passed) | 1 | Microsoft Graph from the sign-in; Exchange Online (`exchange_policy`) minted silently from the same sign-in. Teams admin, Power BI, Power Platform and Security & Compliance are not collected in delegated mode and never prompt |
| Delegated, Azure CLI token (`--use-azure-cli-token`, and guided `gr-audit` without a sign-in app id and without Exchange) | 0 inside Auditex | Microsoft Graph from the operator's existing Azure CLI sign-in (one `az login` made before the run and reused until it expires). Auditex never runs `az login` during a run |
| Access token (`--access-token`) | 0 | Microsoft Graph only |

One-time set-up steps, each counted on its own:

| Set-up step | Sign-ins (once) |
|---|---|
| App registration, permissions, admin consent, role assignment and certificate upload in the Microsoft Entra admin centre | 1 administrator sign-in covers all of them; creating the certificate and its key needs none |
| Delegated Exchange permission on the sign-in app (`Exchange.Manage`, admin consent) | 0 when added in the same Entra admin centre session, otherwise 1 |
| Security & Compliance permission on the audit app (`Exchange.ManageAsApp` on **Microsoft Exchange Online Protection**, admin consent) | 0 when added in the same Entra admin centre session as the app registration, otherwise 1 |
| Guided `ga-setup-app` (saves the Microsoft 365 CLI app as the sign-in app) | At most 3 browser sign-ins: `az login` (skipped when Azure CLI is already signed in to the tenant), the Microsoft 365 CLI setup's own sign-in (it signs in as Azure CLI to create the app) and the `m365 login` check (skipped when the CLI is already signed in) |
| Power BI read-only admin API setting (Fabric admin portal) | 1 sign-in to the Fabric admin portal |
| Power Platform management-app registration (`Add-PowerAppsAccount`, `New-PowerAppManagementApp`) | 1 sign-in with the Power Apps administration module |
| Installing `pwsh` and `ExchangeOnlineManagement` | 0 |

### Delegated Read Login

Use this when an operator signs in with a tenant account.

Recommended role:

- Global Reader for broad audit coverage.

Useful narrower roles:

- Security Reader for security posture.
- Reports Reader for usage and report surfaces.
- Exchange admin or Exchange reader tooling only when Exchange command coverage is explicitly in scope.

Command shape, one sign-in inside the run (Exchange included when selected; sign-in app requirements under
[Exchange Online in a delegated run](#exchange-online-in-a-delegated-run)):

```bash
auditex guided-run --flow gr-audit --include-exchange --client-id <sign-in-app-id> --tenant-id <tenant-id-or-domain>
```

Command shape with an existing Azure CLI sign-in (no Exchange; the operator runs `az login` once, before the run):

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

#### Certificate credential for app-only runs

An app-only run authenticates with a client secret or with a certificate, never both. A certificate is needed for the Teams admin policies (`teams_policy`): the Teams admin API accepts only a certificate-minted token, so a secret-only run records `teams_token_unavailable` for its seven operations. It is also needed for the Security & Compliance reads of `exchange_policy` (alert and DLP policies), which a secret-only run records as `ipps_session_not_opened`. With a certificate, Auditex mints every app token (Microsoft Graph, Exchange Online, Security & Compliance, the Teams admin API and the optional Power BI and Power Platform resources) from it through `msal.ConfidentialClientApplication`; the client-secret path is unchanged for runs that use a secret.

Set-up, by the customer's administrator:

1. Create an RSA certificate of at least 2048 bits under the customer's key-management policy, with an expiry no later than the audit engagement needs. A self-signed certificate is accepted by Entra.
2. Upload the **public** certificate (`.cer` or `.pem`, no private key) to the audit app registration under Certificates & secrets > Certificates, and note the SHA-1 thumbprint the portal shows. This adds a key credential to the app; it is a tenant change made by the administrator, never by Auditex.
3. Keep the private key as a PEM or PFX file on the audit workstation, readable only by the operator account (mode `600`; Auditex refuses a key file that its group or others can read, a symbolic link, a non-regular file or one over 64 KiB). If the key is encrypted, keep its password in a separate owner-only file or supply it through an environment variable.
4. Run with `--client-id <app-id> --certificate-path <key file> --certificate-thumbprint <sha1>` and, for an encrypted key, `--certificate-password-file <file>` or `--certificate-password-env <variable name>`. No option takes the password or key text itself.

Blast radius of the key credential: anyone holding the private key (and its password) can sign in as the audit app from anywhere, with every application permission and directory role the app holds, until the certificate expires or is removed from the app registration. For the reader app that is the read-only Graph application permissions, `Exchange.ManageAsApp` (on Office 365 Exchange Online and, when added for the alert and DLP reads, on Microsoft Exchange Online Protection) with Global Reader and the Teams admin read with Global Reader; it grants nothing the app does not already hold, and no write permission is added. Remove the key credential from the app registration when the engagement ends, and delete the private key file.

What Auditex does with it: the key file and password are read once, before the run folder exists or any request is made, and checked (RSA of at least 2048 bits; when the file carries the certificate, it must match the key and the thumbprint and be within its validity dates). The password environment variable is removed from the process environment as soon as it is read, so PowerShell and other child processes do not inherit it. The key stays in process memory, as do tokens (msal's cache is in memory only); none of the key, its password, the assertion or a token is written to the run folder, the audit log, the API ledger, the console or an error message. The `--certificate-*` options are redacted from the recorded command line, and every failure is a fixed message naming the cause (file refused, password unavailable, key unreadable, thumbprint mismatch, certificate not valid, authority refused, token not acquired), never a path, value or service diagnostic. The client assertion is sent only to an HTTPS Microsoft Entra authority (`login.microsoftonline.com`, `login.microsoftonline.us`, `login.chinacloudapi.cn`, `login.partner.microsoftonline.cn`). A certificate together with `--client-secret`, `--access-token`, `--auth-context`, `--interactive` or `--use-azure-cli-token` is refused before any request; a saved `AZURE_CLIENT_SECRET` is ignored with a warning and never sent. `auditex probe live` does not take a certificate yet; run the probe with a secret or rely on `--probe-first` in the certificate run.

### Exchange-Assisted Coverage

Exchange posture can use Microsoft 365 CLI and PowerShell adapters where Graph has poor coverage. Auditex still records the command surface and keeps audit output read-only. Do not use production write commands.

Detection coverage reads `Get-AdminAuditLogConfig`, `Get-OrganizationConfig`, and `Get-MailboxAuditBypassAssociation` in Exchange Online PowerShell, and `Get-ProtectionAlert` in Security & Compliance PowerShell, which opens only in app-only certificate runs (see [Security & Compliance in app-only certificate runs](#security--compliance-in-app-only-certificate-runs)). These are read-only `Get-*` cmdlets; View-Only Organization Management or Global Reader is sufficient. Without a session the signal is reported as `unknown`, not `off`.

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
https://www.googleapis.com/auth/admin.directory.user.readonly,https://www.googleapis.com/auth/admin.directory.group.readonly,https://www.googleapis.com/auth/admin.directory.domain.readonly,https://www.googleapis.com/auth/admin.directory.orgunit.readonly,https://www.googleapis.com/auth/admin.directory.rolemanagement.readonly,https://www.googleapis.com/auth/admin.directory.user.security,https://www.googleapis.com/auth/admin.reports.audit.readonly,https://www.googleapis.com/auth/admin.reports.usage.readonly,https://www.googleapis.com/auth/apps.alerts,https://www.googleapis.com/auth/cloud-identity.policies.readonly,https://www.googleapis.com/auth/gmail.settings.basic,https://www.googleapis.com/auth/admin.directory.device.mobile.readonly,https://www.googleapis.com/auth/admin.directory.device.chromeos.readonly
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

A finding built from `admin`-scoped evidence says so in its description and in `subject_scoped: admin`; do not present it as an organisation-wide result. The per-user token is narrowed to `gmail.settings.basic`, so the token that can act as any user does not carry the other scopes in the delegation entry. The service account must be allowed to impersonate every user for the Gmail settings; a refused impersonation is a failed `mailboxSettings:<user>` row, and all of them together raise one `google.collector_issue` for the surface with the count of mailboxes.

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

Exchange policy, audit, and forwarding checks run read-only `Get-*` cmdlets. In app mode Auditex requests an Exchange Online token for the audit app (`https://outlook.office365.com/.default`) and connects with `Connect-ExchangeOnline -AccessToken` against the tenant's initial `.onmicrosoft.com` domain; the token is passed to PowerShell through an environment variable, never on the command line. This needs the `Exchange.ManageAsApp` application permission on Office 365 Exchange Online plus a read role for the service principal, such as Global Reader ([Microsoft guidance](https://learn.microsoft.com/powershell/exchange/app-only-auth-powershell-v2)). Without them the checks are reported as `session_not_connected` or `command_not_authenticated` coverage gaps. `Get-ProtectionAlert` and the DLP reads need a Security & Compliance PowerShell session; see the next section.

### Security & Compliance in app-only certificate runs

Alert policies (MS.SECURITYSUITE 4.1) and DLP policies (MS.SECURITYSUITE 3.1-3.4) are read in Security & Compliance PowerShell. In an app-only run with a certificate credential, Auditex mints, silently from the same certificate, an app-only token for the **Microsoft Exchange Online Protection** resource (`https://ps.compliance.protection.outlook.com/.default`) and connects with `Connect-IPPSSession -AccessToken` against the tenant's initial `.onmicrosoft.com` domain; the token reaches PowerShell through an environment variable, never the command line, and no sign-in window opens. Before connecting, Auditex checks that the token is an app-only certificate token for that audience; anything else opens no session. Each read runs in its own short PowerShell process that connects first, and a connect that fails stops the reads that follow.

This needs, once, from the customer's administrator:

1. The application permission `Exchange.ManageAsApp` on the **Microsoft Exchange Online Protection** API (APIs my organization uses > Microsoft Exchange Online Protection > Application permissions; resource app id `00000007-0000-0ff1-ce00-000000000000`), with admin consent. This is a second consent beside the Office 365 Exchange Online one, on a different resource ([Microsoft guidance](https://learn.microsoft.com/powershell/exchange/app-only-auth-powershell-v2)).
2. A supported read role on the service principal: Global Reader, which the reader app already holds, is on Microsoft's list of roles for app-only Security & Compliance PowerShell. No further role is needed.
3. `ExchangeOnlineManagement` 3.8.0 or later on the audit workstation (the first version whose `Connect-IPPSSession` takes `-AccessToken`, [reference](https://learn.microsoft.com/powershell/module/exchangepowershell/connect-ippssession)).

Blast radius of the added permission: `Exchange.ManageAsApp` on Microsoft Exchange Online Protection lets the app open Security & Compliance PowerShell with the permissions of the directory role assigned to it. With Global Reader that is read-only visibility of the tenant's compliance configuration (alert, DLP, retention and similar policies); Auditex issues only the four reads below, from the read allow-list, and never a mutating cmdlet. Remove it under API permissions on the app registration.

The reads, all read-only `Get-*` cmdlets:

- `Get-ProtectionAlert`: alert policy `Name`, `Disabled`, `Severity`, `Category`, `IsSystemRule`.
- `Get-Command Get-DlpCompliancePolicy`: a count only, whether the session offers the DLP cmdlets (the DLP licence fact, read the way ScubaGear reads it). A count of 0 skips the two DLP reads as `dlp_licence_not_detected`, and SS 3.1-3.4 read "licence not detected", not assessed.
- `Get-DlpCompliancePolicy`: `Name`, `Enabled`, `Mode`, `Workload` and the five location lists, written as text; every location entry other than `All` is stored as the placeholder `location`.
- `Get-DlpComplianceRule`: `Name`, `ParentPolicyName`, `Disabled`, `IsAdvancedRule`, `AdvancedRule`, `ContentContainsSensitiveInformation`, `BlockAccess`, `BlockAccessScope`, `NotifyUser` (stored as same-length `recipient` placeholders) and `NotifyUserType`. A failed DLP read keeps only the length of its output (`stdout_bytes`).

A client-secret, delegated or access-token run opens no Security & Compliance session and asks for no token for it (no Microsoft source shows a secret-minted token is accepted): the four reads record the section-scoped gap `ipps_session_not_opened` and the five rows are not assessed. So does a connect that fails (missing consent or role, an older module); the failure is named, never a pass, and the Exchange reads keep the collector's status.

The same Exchange session reads `Get-SharingPolicy` (`Name`, `Domains`), readable with Global Reader, the role ScubaGear's own prerequisites list for this cmdlet. It uses the existing grants and reads partner-sharing configuration without message content. `Get-OrganizationConfig` includes `Identity`, `Name`, `AuditDisabled`; `Get-TransportConfig` includes `Name`, `SmtpClientAuthenticationDisabled`; `Get-TransportRule` includes `State`, `Mode`, `FromScope`, `PrependSubject` in its explicit configuration field list. The same session reads `Get-AcceptedDomain` with `Name`, `DomainName`, `DomainType`, `Default`, `IsCoexistenceDomain`. Complete same-run accepted-domain evidence supplies the SPF, DKIM and DMARC raw-record universe: domain names de-duplicated case-insensitively with the first-seen spelling retained and coexistence rows excluded. When both collectors are selected, `dns_posture` runs after `exchange_policy` and reuses that evidence without another tenant read or additional grants. Missing, failed, truncated or malformed evidence falls back to verified domains with the Email service; missing or non-list Graph `supportedServices` is kept. Coverage records `domain_universe` as `accepted_domains` or `graph_email_service`. These TXT lookups use public DNS without sign-in, retain the 200-domain record cap and fail-closed behaviour, and leave posture checks over all verified domains unchanged.

### Exchange Online in a delegated run

The one-sign-in delegated route needs a sign-in app registered in the customer tenant (the app
`ga-setup-app` saves, or any app passed with `--client-id`): a public client with the **Mobile and desktop
applications** redirect URI `http://localhost` (the sign-in opens the browser and returns to a local port), the
delegated Microsoft Graph permissions the selected collectors need, with admin consent, and for Exchange the
delegated permission `Exchange.Manage` on **Office 365 Exchange Online**, with admin consent. The run signs in once
for Microsoft Graph, then asks the same in-memory token cache, silently, for an Exchange Online token for
`https://outlook.office365.com/.default` and connects with
`Connect-ExchangeOnline -AccessToken <token> -UserPrincipalName <signed-in user>`; the token and the user name
reach PowerShell through environment variables, never the command line, and the cache is never written to disk.
Sources: the [Connect-ExchangeOnline reference](https://learn.microsoft.com/powershell/module/exchangepowershell/connect-exchangeonline)
(`-AccessToken`, module 3.1.0-Preview1 or later, used with `-Organization`, `-DelegatedOrganization` or
`-UserPrincipalName` by token type) and the
[Exchange Online token guidance](https://learn.microsoft.com/exchange/reference/admin-api-authentication)
(the `https://outlook.office365.com/.default` scope, and the Exchange role the signed-in user needs);
`Exchange.Manage` is the delegated permission the Office 365 Exchange Online API publishes, listed under
API permissions > Office 365 Exchange Online > Delegated permissions in the Entra admin centre, and the
token's `scp` claim must carry it. The signed-in user needs an Exchange read role such as Global Reader or
View-Only Organization Management. Without the permission or the role, the Exchange checks are coverage gaps
(`session_not_connected` or `command_not_authenticated`), never a second sign-in. The Security & Compliance reads
(`Get-ProtectionAlert` and the DLP reads) stay a named skip (`ipps_session_not_opened`) in delegated runs.

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
   (security-enabled, not mail-enabled, not role-assignable) and add the customer-owned
   audit app's service principal as its only member. In the Fabric admin portal, open
   Tenant settings > Admin API settings; enable **Service principals can access read-only
   admin APIs** (API setting name `AllowServicePrincipalsUseReadAdminAPIs`) for **Specific
   security groups**, selecting that group only. This is not the MS.POWERBI.4.1 setting
   **Service principals can call Fabric public APIs** (`ServicePrincipalAccessPermissionAPIs`);
   leave that one as it is. Do not grant any Power BI API permission, and never grant
   `Tenant.Read.All`: Microsoft requires that an app calling the read-only admin APIs this
   way has no admin-consent-required Power BI permissions. Changes can take up to 15 minutes
   to apply.
   - **Blast radius:** the group's service principals get read-only access to all the
     information the Power BI admin APIs expose, now and in future (Microsoft Learn: for
     example user names and emails, semantic model and report detailed metadata). It
     grants no write. Keep the group's membership to the audit app alone.
   - **Exact removal:** in the same place set **Service principals can access read-only
     admin APIs** back to **Disabled** (or, if other groups still need it, remove only the
     audit group from **Specific security groups**), Apply; then delete the security group
     in the Entra admin centre (Groups > the group > Delete). A deleted security group
     is not kept in deleted items. With the Fabric admin API the same change is
     `POST https://api.fabric.microsoft.com/v1/admin/tenantsettings/AllowServicePrincipalsUseReadAdminAPIs/update`
     with `{"enabled": false, "enabledSecurityGroups": []}` (delegated `Tenant.ReadWrite.All`,
     Fabric Administrator).
   The alternative operator role is Fabric Administrator with a Power BI or Fabric licence
   and at least one prior sign-in to the Power BI portal. It is a write-capable admin role
   used read-only, with tenant-wide Power BI/Fabric administrative blast radius. This
   operator route is a prerequisite reference, not a working delegated token path in Auditex.
2. **Power Platform management-app route first:** an authorised customer administrator
   (Global Administrator or Power Platform Administrator) signs in interactively with the
   Power Apps administration module (`Add-PowerAppsAccount -Endpoint prod -TenantID <tenant id>`)
   and performs the one-time registration
   `New-PowerAppManagementApp -ApplicationId <app id>` for the customer-owned audit app
   (REST: `PUT https://api.bap.microsoft.com/providers/Microsoft.BusinessAppPlatform/adminApplications/<app id>?api-version=2020-10-01`,
   no body). A service principal cannot register itself. This registration is a
   customer-side write.
   - **Blast radius:** Microsoft Learn states that a registered service principal is
     "treated within Power Platform like how normal users are with the Power Platform
     Administrator role assigned. Granular roles and permissions can't be assigned to
     limit their capabilities." Anyone holding the audit app's credential can therefore
     administer environments, data policies, tenant settings and Power Apps across the
     tenant, read and write, until the registration is removed. It adds no Entra role
     and no API permission. Auditex itself only reads.
   - **Exact removal:** `Remove-PowerAppManagementApp -ApplicationId <app id>` in the same
     signed-in session (REST: `DELETE https://api.bap.microsoft.com/providers/Microsoft.BusinessAppPlatform/adminApplications/<app id>?api-version=2020-10-01`);
   `Get-PowerAppManagementApps` then no longer lists it. Remove it when the audit is done,
     and before deleting the app registration itself.
   The alternative operator role is Power Platform Administrator with a Power Apps for
   Office 365 licence. It is a write-capable admin role used read-only; it can administer
   environments and policy across the tenant. Auditex itself writes nothing. This operator
   route likewise does not supply a delegated token path in Auditex.

In app mode each collector obtains its own token through `app_token_for`, using
`https://service.powerapps.com//.default` (the double slash is intentional) and
`https://analysis.windows.net/powerbi/api/.default`. Do not supply a separate bearer
token. Configure the app authentication locally using the existing app-mode process.
See the selected collector notes in
`auditex setup-guide m365 --collector-preset power-platform --plane inventory --mode app --format json`.
The JSON guide includes these setup requirements only when the collectors are selected.

Every request is a read: GET, plus one body-free POST for Power Platform
`listTenantSettings`, which Microsoft documents as a POST with no request body. Power Platform returns environment id/name, SKU, default
status and creation time; environment display names are discarded because developer
and trial environments can be named after people and no rule reads that field. DLP
policy display names remain because the rules read them. Other reads retain DLP
connector counts and environment scope, environment-creation and sharing flags, and
the tenant-isolation disabled flag. Power BI retains tenant setting names, enabled
values and security-group ids, plus a local access-denial observation. Neither
collector reads message bodies or file content. The exact endpoints, API versions
and retained fields are in the [API call catalogue](../reference/api-call-catalog.md#optional-power-platform-and-power-bi).

`listTenantSettings` is a read sent as a body-free POST with `api-version=2020-10-01`
(`TENANT_SETTINGS_METHOD = "POST"`), as Microsoft documents it ("List tenant settings":
POST, "Don't supply a request body for this method"). The client admits POST for that one
path only and sends no body; every other Power Platform request is GET.

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

Prerequisite reference: ScubaGear revision `2446ad723b7f55031cc02c8aca244d731d468cba`.
The Power BI tenant setting and Power Platform registration it requires for app-only runs
are described in [Power Platform and Power BI (optional)](#power-platform-and-power-bi-optional);
operator roles, licences and prior portal sign-in are described there too.

### Teams policy reads in app-only runs

The Teams policy reader uses certificate authentication for audience `48ac35b8-9aa8-4d74-927d-1f4a14a0b239` (scope `48ac35b8-9aa8-4d74-927d-1f4a14a0b239/.default`) and the read-only **Global Reader** directory role assigned to the audit service principal. It adds no Graph scope or write permission. The reader sends only five allowlisted HTTPS GETs to `api.interfaces.records.teams.microsoft.com`, for meeting policies, federation settings, client configuration, app permission policies and broadcast policies. Only consumed policy fields are stored; the REST mapping omits the unused `AllowIPVideo` and `ScreenSharingMode` fields while PowerShell selects stay unchanged; no message, chat, channel or file content is read. Tokens stay in memory and HTTP authorisation headers, never logs, bundle files or command lines.

Each REST operation caps decoded response bodies at 4 MiB in total across both attempts (including error responses), with a 90-second monotonic deadline covering requests, body reads and its single retry. Oversized responses yield `response_too_large`; an expired deadline yields `timeout`, withholding all rows. At the deadline the reader shuts down an accessible response socket to interrupt a blocked body read; the worker then closes the response. Before response headers arrive, or if the transport exposes no socket, the worker may remain for as long as the peer keeps sending, then up to the 30-second socket inactivity timeout; it holds the token in memory only. Successful responses require `application/json`, UTF-8 (optionally with a UTF-8 BOM), no NUL bytes, an object or non-empty `value` list envelope, all required policy fields with the expected types, and at most 32 JSON container levels scanned and parsed from the same decoded text. Malformed evidence yields `unexpected_shape`; top-level arrays, error envelopes and partial pages are withheld. Empty responses are also withheld for all five operations: the configurations are singletons and each policy family includes Global. The downstream Teams adapters can propagate a complete empty operation as `[]`, so this anomaly must be rejected by the reader. An empty `AllowedDomains` field inside a valid federation row remains legal.

Commercial and GCC are supported; GCC High, DoD and unknown environments are not collected (`unsupported_environment`) and make no Teams admin API call. In supported environments, without a usable certificate token, all seven operations are `skipped` with reason `teams_token_unavailable`, without attempting any `Get-Cs*` command or Teams admin API read. The collector completes `ok`; Teams alone does not make the run partial or return exit code 1. The coverage gaps, report pack and handoff state "not collected: certificate token for the Teams admin API not available" and the policies remain not assessed, never a pass or not applicable. In unsupported environments the five REST operations retain their `unsupported_environment` failures; the two command operations skip without a token. A service refusal with a usable token or a missing role yields `command_not_authenticated`, never a pass. With a usable token, messaging and app setup policies are still skipped as coverage gaps with reason and collector error class `teams_powershell_not_supported` ("not collected: Teams PowerShell sessions are not supported"); no PowerShell command is attempted. Auditex has no Teams PowerShell connection path in any authentication mode.

Certificate authentication is evidenced by ScubaGear at pinned commit `2446ad72`, `Modules/Connection/Connection.psm1` (`Get-MsalAccessToken -CertificateThumbprint` for the Teams scope); its API catalogue specifies Global Reader. In an app-mode run with a certificate credential (see "Certificate credential for app-only runs" above) Auditex mints the Teams admin token from it through msal and the five REST reads run (meeting policies, broadcast policies, federation configuration, client configuration and app permission policies), covering every Teams section the assessed SCuBA policies cite. The other two Teams operations, messaging policies (`Get-CsTeamsMessagingPolicy`) and app setup policies (`Get-CsTeamsAppSetupPolicy`), stay named skips with reason `teams_powershell_not_supported` in every app-only run, certificate included: they have no Teams admin REST read and would need a Teams PowerShell session, which Auditex does not open, and no assessed SCuBA policy cites them. A secret-only run never asks for a Teams token and records `teams_token_unavailable`, and a delegated run is unchanged. The `global-reader` profile and the `full` preset select `teams_policy` for app-mode runs. The reader requires the Teams audience and certificate credential claim (`appidacr` or `azpacr` equal to `2`); the service validates the token itself.

Client-secret token acceptance was **not verified live** (playground check not run) and that credential path is disabled for Teams policy reads. Certificate-authenticated reads and actual REST response shapes have also not been verified live. Org-wide `tenant_app_settings` remain uncollected on app-only runs, so TEAMS 5.1-5.3 remain not assessed; no certificate marker is synthesised to bypass that gap.
