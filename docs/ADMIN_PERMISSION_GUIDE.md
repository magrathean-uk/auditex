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
- Intune may be absent,
- audit/sign-in log history may be limited,
- some SharePoint or Exchange depth may need extra role or app-only coverage.

Auditex records these as blockers in `live-readiness.json` and `audit-plan.json`.

### App-Readonly

Use this when a customer grants an app registration for repeatable read-only audits.

Typical Microsoft Graph application permissions depend on selected collectors, but commonly include:

- `Directory.Read.All`
- `User.Read.All`
- `Group.Read.All`
- `RoleManagement.Read.Directory`
- `Policy.Read.All`
- `AuditLog.Read.All`
- `Reports.Read.All`
- `Application.Read.All`
- `DelegatedPermissionGrant.Read.All`
- `SecurityEvents.Read.All` or related security permissions where Defender/Security APIs are in scope.
- `DeviceManagementManagedDevices.Read.All` and related Intune read scopes where Intune is in scope.

Use `auditex probe live --mode app` before full collection. Do not grant write permissions for the audit path.

### Exchange-Assisted Coverage

Exchange posture can use Microsoft 365 CLI and PowerShell adapters where Graph has poor coverage. Auditex still records the command surface and keeps audit output read-only. Do not use production write commands.

## Google Workspace Access Models

### Domain-Wide Delegation

Domain-wide delegation is the preferred path for full-domain Google Workspace coverage. It uses:

- a Google Cloud service account,
- the service account OAuth client ID,
- an Admin Console domain-wide delegation entry,
- a delegated subject admin such as `admin@example.com`,
- explicit OAuth scopes.

In Google Admin Console:

1. Open Security > Access and data control > API controls > Domain-wide delegation.
2. Add the service account client ID.
3. Paste the comma-separated scopes for the collector preset you intend to run.
4. Save, then wait a few minutes before probing.

Core scopes:

```text
https://www.googleapis.com/auth/admin.directory.user.readonly,https://www.googleapis.com/auth/admin.directory.group.readonly,https://www.googleapis.com/auth/admin.directory.domain.readonly,https://www.googleapis.com/auth/admin.directory.orgunit.readonly,https://www.googleapis.com/auth/admin.directory.rolemanagement.readonly,https://www.googleapis.com/auth/admin.directory.device.mobile.readonly,https://www.googleapis.com/auth/admin.directory.device.chromeos.readonly,https://www.googleapis.com/auth/admin.directory.user.security,https://www.googleapis.com/auth/admin.reports.audit.readonly,https://www.googleapis.com/auth/admin.reports.usage.readonly,https://www.googleapis.com/auth/apps.alerts,https://www.googleapis.com/auth/gmail.settings.basic,https://www.googleapis.com/auth/gmail.settings.sharing
```

Everything preset additional scopes:

```text
https://www.googleapis.com/auth/drive.metadata.readonly,https://www.googleapis.com/auth/drive.readonly,https://www.googleapis.com/auth/apps.groups.settings,https://www.googleapis.com/auth/admin.directory.resource.calendar.readonly,https://www.googleapis.com/auth/calendar.calendarlist.readonly,https://www.googleapis.com/auth/calendar.acls.readonly
```

`drive.readonly` is broad. Auditex does not read Drive file content, but Google may require broad scope for some metadata or permission surfaces. The data-handling and API inventory artifacts declare the scope risk and no-content-read claim.

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
