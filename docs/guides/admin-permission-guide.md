# Auditex Administrator Permission Guide

This guide tells a tenant administrator what access Auditex needs and why. Auditex is audit-only: requested access is for evidence collection and report generation, not production fixes.

Before granting anything, generate the exact plan for the intended coverage:

```bash
auditex setup-guide m365 --auditor-profile global-reader --collector-preset full --format md
auditex setup-guide google --auth domain-delegation --collector-preset everything --format md
```

Use the generated plan as the admin request. It includes selected collectors, required scopes or Graph permissions, setup steps, verification commands, and read-only assertions.

## Microsoft 365 Access Models

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

Detection coverage reads `Get-AdminAuditLogConfig`, `Get-OrganizationConfig`, and `Get-MailboxAuditBypassAssociation` in Exchange Online PowerShell, and `Get-ProtectionAlert` in Security & Compliance PowerShell (`Connect-IPPSSession`). These are read-only `Get-*` cmdlets; View-Only Organization Management or Global Reader is sufficient. Without the session the signal is reported as `unknown`, not `off`.

Mail protection reads `Get-MalwareFilterPolicy` (the common attachment types filter and zero-hour auto purge of every policy, the default one and custom ones), `Get-TransportConfig` (`SmtpClientAuthenticationDisabled`), `Get-CASMailbox` (only a count of the mailboxes that switch SMTP AUTH back on for themselves; it enumerates every mailbox, which takes longer in a large tenant) and `Get-DkimSigningConfig` (DKIM signing per domain) in the same Exchange Online session. They are read-only `Get-*` cmdlets that pass the shared read guard and need no role beyond Global Reader. Without the session the matching rules read `not_assessed`, never a pass.

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

Exchange policy, audit, and forwarding checks run read-only `Get-*` cmdlets. In app mode Auditex requests an Exchange Online token for the audit app (`https://outlook.office365.com/.default`) and connects with `Connect-ExchangeOnline -AccessToken` against the tenant's initial `.onmicrosoft.com` domain; the token is passed to PowerShell through an environment variable, never on the command line. This needs the `Exchange.ManageAsApp` application permission on Office 365 Exchange Online plus a read role for the service principal, such as Global Reader ([Microsoft guidance](https://learn.microsoft.com/powershell/exchange/app-only-auth-powershell-v2)). Without them the checks are reported as `session_not_connected` or `command_not_authenticated` coverage gaps. `Get-ProtectionAlert` needs a Security & Compliance PowerShell session, which Auditex does not open, so alert policies stay a coverage gap in app mode.
