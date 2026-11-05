# Auditex Setup Guide

Run this before a live audit:

```bash
auditex setup-guide google --collector-preset everything --format md
auditex setup-guide m365 --auditor-profile global-reader --collector-preset full --format md
```

The command prints:

- selected collectors,
- Google Workspace OAuth scopes or Microsoft Graph permissions,
- admin setup steps,
- probe and run commands,
- read-only and no-content-read assertions,
- primary vendor documentation links.

Auditex builds this output from the shipped scope catalog. The same catalog also feeds capability rows and permission ledgers so access planning stays consistent across setup, run, and review surfaces.

Use JSON for AI/MCP callers:

```bash
auditex setup-guide google --collector-preset everything --format json
auditex setup-guide m365 --collector-preset full --format json
```

## Google Workspace

Preferred path (domain-wide delegation reads each user's Gmail settings as that user; Drive and Calendar evidence is the delegated admin's view and is labelled `subject_scoped: admin`, see the admin permission guide):

```bash
auditex setup-guide google --auth domain-delegation --collector-preset everything --domain example.com --subject admin@example.com
```

Admin flow:

1. Enable the APIs listed by the guide.
2. Create a delegated service identity in Google Cloud.
3. Copy its OAuth app ID.
4. In Admin Console, open Security > Access and data control > API controls > Domain-wide delegation.
5. Add the OAuth app ID and paste the generated comma-separated scopes. The 2-step verification policy needs `cloud-identity.policies.readonly` and the Cloud Identity API.
6. Run the generated doctor and probe commands.

`--domain` is a label. Users and groups are listed for the whole customer, and the internal domains (primary, secondary and alias) come from the Directory domains list.

Accepted risks go in a waiver file, the same JSON format as the Microsoft 365 run. Each waiver names a `finding_id` or a `rule_id` (a `collector` or `category` only narrows it), and an expired waiver is ignored. An invalid file stops the run before any API call:

```bash
auditex google run --auth domain-delegation --service-account-key key.json --subject admin@example.com \
  --domain example.com --waiver-file waivers.json --stale-user-days 90 --stale-device-days 90
```

`--stale-user-days` sets how long an active account may go without signing in; `--stale-device-days` sets how long a managed mobile or ChromeOS device may go without syncing before `google.mobile_device_stale_sync` or `google.chromeos_device_stale_sync` reports it. Both default to 90.

OAuth mode is available for development or partial review:

```bash
auditex setup-guide google --auth oauth --collector-preset core-security
```

Treat OAuth output as partial if domain-wide admin surfaces are blocked. OAuth cannot act as another user, so Gmail settings cover the signed-in mailbox only and the run says so.

## Microsoft 365

Preferred first pass:

```bash
auditex setup-guide m365 --mode delegated --auditor-profile global-reader --collector-preset full --tenant-id contoso.onmicrosoft.com
```

Admin flow:

1. Assign the operator the read-only role shown in the guide.
2. Sign in with Azure CLI.
3. Run the generated probe command.
4. Review `live-readiness.json`, `audit-plan.json`, and `diagnostics.json`.
5. Add only the missing read permission or role justified by the probe.
6. Rerun probe before full collection.

App-only repeat runs:

```bash
auditex setup-guide m365 --mode app --auditor-profile app-readonly-full --collector-preset full --tenant-id contoso.onmicrosoft.com
```

The app registration must be customer-owned. Add only the listed Microsoft Graph application permissions and grant tenant-wide admin consent.

### Customer-owned certificate credentials

1. Create an RSA certificate (at least 2048 bits) under the customer's key-management policy.
2. **Upload the certificate (.cer, public part only) to the app registration** under Certificates & secrets > Certificates. Never upload or share its private key or PFX password.
3. Select that certificate for the audit run with one of the engine CLI options below. Certificate mode ignores a saved `AZURE_CLIENT_SECRET`; do not pass `--client-secret` or a delegated/token credential alongside it.

For a customer-local PFX, supply its password through an environment variable populated by the customer's approved secret mechanism. Pass only the variable's **name**, never its value, on the command line:

```bash
azure-tenant-audit --tenant-name CUSTOMER --tenant-id CUSTOMER_TENANT --client-id CUSTOMER_APP \
  --certificate-pfx /customer-managed/audit.pfx --certificate-password-env CUSTOMER_PFX_PASSWORD
```

The PFX must be an encrypted regular file, at most 64 KiB, with permissions `0600` (no group or other access). Auditex opens it read-only and checks the opened descriptor before a bounded read. An unencrypted PFX contains an unprotected private key and is refused by default. The explicit `--certificate-allow-unencrypted-pfx` option, or `PfxCertificate(..., allow_unencrypted=True)` for embedded callers, permits one but is discouraged; it does not relax permissions or the size limit.

For a macOS keychain identity, select the public certificate's SHA-256 fingerprint (64 hexadecimal characters):

```bash
azure-tenant-audit --tenant-name CUSTOMER --tenant-id CUSTOMER_TENANT --client-id CUSTOMER_APP \
  --certificate-keychain-sha256 CUSTOMER_CERTIFICATE_SHA256
```

The keychain identity must include an RSA private key available for signing to the audit process under its keychain access policy. Auditex uses Security.framework to sign through an opaque key handle; it never exports that private key. Locked, missing or inaccessible identities fail closed. If macOS asks for access, choose **Allow**, never **Always Allow**: trusting the generic Python interpreter permanently lets any Python program run by that user sign as the audit app. Headless or SSH use needs the customer to set the key's ACL beforehand, with that interpreter-wide trust risk understood.

**Inference, not run:** `kSecUseAuthenticationUIFail` does not suppress the legacy file-keychain ACL signing dialog. The fail-closed behaviour for locked or missing identities does not imply that this dialog cannot appear. Native keychain on a real Mac, including ACL prompts, one-time Allow and headless/SSH behaviour, remains a customer-authorised live validation gate before release.

Embedded callers select `AuthConfig(..., auth_mode="app", client_secret=None, certificate=PfxCertificate(path, password_env="CUSTOMER_PFX_PASSWORD"))` or `certificate=KeychainCertificate(sha256_hex)`. Import these credential classes from `azure_tenant_audit.certificate_auth`. Credential construction consumes and removes the named password variable from Auditex's `os.environ` before collectors start; refreshes use a process-local password-provider closure. Later child processes do not inherit that variable. This cannot clear the launching shell's environment or guarantee erasure of operating-system environment snapshots. A PFX password callable is also supported as `password_provider=callable`; no literal password field exists. The run context's `client.app_token_for(scope)` returns the raw access-token string or raises a fixed `CertificateAuthError`; it performs no disk caching. The same certificate supplies the Graph token through `ensure_token()`.

No secret leaves the customer for Auditex or the auditor. The original customer-managed PFX stays on disk under the customer's protection; Auditex reads it into memory without making a copy, while a keychain-held private key stays in the keychain. The consumed PFX password and cached tokens remain in process memory for use and refresh; Python does not guarantee memory zeroisation. Authentication sends a short-lived signed assertion directly to Microsoft's tenant token endpoint, and API calls send the resulting bearer token to the selected Microsoft resource. Neither is written to audit evidence or logs by this path. Do not enable external wire tracing, debugger local-variable capture or process dumps while handling credentials. Live release gates are native keychain on a real Mac, Teams admin API acceptance of certificate tokens, and service acceptance of RS256 with `x5t#S256`; all remain unverified.

Protocol reference: [Microsoft identity platform certificate credentials](https://learn.microsoft.com/en-us/entra/identity-platform/certificate-credentials). **Inference, offline implementation:** the established RS256 flow is used with `x5t#S256`, tenant token endpoint audience, app ID issuer/subject, unique `jti`, `nbf` and a five-minute expiry. The current Learn page and service acceptance were not checked online.

Emergency access accounts: tell the Conditional Access check which accounts they are, so that it does not rely on inference. Pass `--break-glass-accounts` to `auditex run` or `azure-tenant-audit` (comma-separated object IDs, user principal names, display names or group names, or `@file` with one per line; an entry is looked up in the full user and group lists, and one that matches nothing, or a display name two accounts share, is reported as unresolved and not judged) or set `AUDITEX_BREAK_GLASS_ACCOUNTS` for any entry point; the option wins over the variable. List the group your policies exclude when the accounts are excluded through it (membership is read only for role-assignable groups). The same list tells the MFA and legacy-authentication checks which exclusions are acceptable: a Conditional Access policy for all users that excludes anything else (an administrator role, a guest type, a staff group) reads "enforced with exclusions" and fails the CIS and ScubaGear controls, so list the accounts even when you do not need the break-glass finding. The finding `ca.break_glass_exclusion_missing` then names each enabled policy that requires MFA or blocks and excludes none of the listed accounts. Without a list the accounts are inferred (names containing break glass or emergency access, and Global Administrator role holders), and the finding is rated medium at most.

```bash
auditex run --tenant-name CONTOSO --tenant-id contoso.onmicrosoft.com --use-azure-cli-token \
  --break-glass-accounts "bg1@contoso.onmicrosoft.com,Break Glass Accounts"
```

## Scope Risk

Some providers expose read evidence through broad or write-capable scope names. Auditex records those as scope risk and still uses only read calls in audit mode.

Verify after every run:

```bash
auditex report api-calls <run-dir> --format md
auditex report permissions <run-dir> --format md
```

## AI And GitHub Use

- Run `auditex setup-guide ... --format json` before asking for admin action.
- Never request permissions not shown in the plan unless a probe proves a missing surface.
- Share only a sanitized setup summary in GitHub issues. Remove tenant identities, domains, local paths, and credentials from generated output first.
- Do not paste auth files or raw tenant evidence into GitHub.
- After live collection, answer from bundle artifacts.

## Primary Sources

- [Google Workspace domain-wide delegation](https://developers.google.com/workspace/guides/create-credentials)
- [Google Admin SDK Directory API](https://developers.google.com/workspace/admin/directory/reference/rest)
- [Google Reports API scopes](https://developers.google.com/workspace/admin/reports/auth)
- [Google Alert Center API scopes](https://developers.google.com/workspace/admin/alertcenter/guides/auth)
- [Gmail API scopes](https://developers.google.com/workspace/gmail/api/auth/scopes)
- [Google Drive files.list scopes](https://developers.google.com/workspace/drive/api/reference/rest/v3/files/list)
- [Google Calendar ACL list scopes](https://developers.google.com/workspace/calendar/api/v3/reference/acl/list)
- [Microsoft Graph app-only access](https://learn.microsoft.com/en-us/graph/auth-v2-service)
- [Microsoft Graph permissions reference](https://learn.microsoft.com/en-us/graph/permissions-reference)
- [Microsoft Entra tenant-wide admin consent](https://learn.microsoft.com/en-us/entra/identity/enterprise-apps/grant-admin-consent)
- [Exchange Online PowerShell](https://learn.microsoft.com/en-us/powershell/exchange/exchange-online-powershell)
