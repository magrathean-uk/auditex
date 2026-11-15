# Auditex Setup Guide

Tenant administrators: every permission, role and setting the reader app needs is in [Reader app permissions](reader-app-permissions.md).

## Default Exchange and public DNS collection

App-mode runs with the `auto` or `global-reader` profile select `exchange_policy`
and `dns_posture` by default, as does the `full` preset. `app-readonly-full` also
includes both. Profile defaults and presets omit both in interactive, delegated and access-token
modes; DNS needs no Exchange session but follows this app-mode default boundary.
Only an explicit `--collectors` list retains these collectors outside app mode.
In delegated mode `--include-exchange` selects the Microsoft 365 CLI
`exchange` collector; it does not select `exchange_policy`. The guided `gr-audit`
flow with Exchange instead passes `exchange_policy` explicitly and reads it over the
run's one sign-in (see Sign-ins per run below).
`config-only` and `power-platform` retain their existing scopes. Power Platform
and Power BI remain opt-in.

A default app-mode run opens an Exchange Online PowerShell session for read-only
`Get-*` policy reads. A delegated run with one sign-in (`--interactive --client-id`)
opens it with an Exchange token minted silently from that sign-in, given the delegated
`Exchange.Manage` permission on the sign-in app; Azure CLI and access-token runs cannot
open it, and each fresh PowerShell process cannot inherit an operator's session.
For app access, install `pwsh` and `ExchangeOnlineManagement`, grant tenant admin
consent to the **Office 365 Exchange Online** application permission
`Exchange.ManageAsApp`, and assign **Global Reader only** to the service principal.
This is a write-capable-named permission used read-only. Its blast radius is
tenant-wide Exchange policy visibility under Global Reader: read-only Get-* cmdlets
only; no mutating cmdlet is issued. A write-capable scope does not authorise tenant
writes. No additional Graph permission is introduced by these defaults.

Alert and DLP policies are read in a Security & Compliance (IPPS) session, which
Auditex opens only in app-only **certificate** runs: a token minted silently from the
certificate for Microsoft Exchange Online Protection is passed to
`Connect-IPPSSession -AccessToken`. It needs `Exchange.ManageAsApp` on **Microsoft
Exchange Online Protection** (a second admin consent) with Global Reader, and
`ExchangeOnlineManagement` 3.8.0 or later; only read-only `Get-*` reads are issued
(see the [admin permission guide](admin-permission-guide.md#security--compliance-in-app-only-certificate-runs)).
A client-secret, delegated or access-token run opens no such session, and a connect
that fails stops the reads that follow: alert and DLP policies are then **not
assessed**, with reason `ipps_session_not_opened`. A session without the DLP cmdlets
skips the DLP reads as `dlp_licence_not_detected`. These section skips leave the
collector and run **ok** when other reads succeed; the gate passes with a named
limitation. The gap remains in coverage, collection gaps, the handoff, explorer and
AI context.

The run sends the tenant's domain names to the public **Cloudflare DNS-over-HTTPS
resolver**, `https://cloudflare-dns.com/dns-query`. Only domain names, no user data,
are sent to that resolver. SPF/DKIM/DMARC TXT lookups cover the tenant's Exchange
accepted domains (coexistence excluded) when the same run collected them, else
Graph verified domains with the Email service. Posture checks and MTA-STS and
public Entra OpenID discovery HTTPS reads stay on Graph-verified domains. No
message bodies or user file content are read. Offline replay performs none of
these requests or sessions. The console, `data-handling.json` and handoff disclose
selected collection activity, without claiming each attempted read succeeded.

Use the existing `--exclude` option to omit either collector or both:

```bash
auditex run --exclude exchange_policy
auditex run --exclude dns_posture
auditex run --exclude exchange_policy,dns_posture
```

Add the usual tenant/auth/output arguments. These flags also work on
`azure-tenant-audit` and `auditex setup-guide m365`. An explicit allowlist such as
`--collectors identity,conditional_access` replaces defaults;
`--collector-preset config-only` omits both. Exclusions apply after profile, preset or explicit selection.
In the guided `gr-audit` flow, answering No to Exchange excludes both Exchange collectors.
Answering Yes reads `exchange_policy` over the run's one sign-in in delegated mode; it needs
the sign-in app id (saved by `ga-setup-app` or passed with `--client-id`) and no longer opens
a Microsoft 365 CLI browser sign-in.
Guided `app-audit` keeps both default policy collectors and honours an explicitly
named or profile-selected Microsoft 365 CLI `exchange` collector. Outside a
`gr-audit` No answer, guided flows add no Exchange exclusion. Generated setup plans derive
the delegated selection from the app selection; each command has its own permissions, tooling
and collection notices, including app requirements in the default delegated guide. An empty
delegated selection is omitted from an app guide with a note.
If an explicit Exchange policy or DNS posture name is removed from a generated
delegated command, its setup steps explain the app-mode-only restriction.
Generated app and delegated probes also retain the probe-only `windows365` surface.

Real Exchange/DNS failures leave dependent policies **not assessed**, with a clear
reason. DNS lookup failures mean unknown records, never absent records. If these
are the only failures, the run is **partial**, collection exits **0**, and the gate
blocks unless `--allow-partial` is supplied. Required collector/authentication
failures retain their non-zero exit behaviour. Missing tooling, consent and real
Exchange session failures retain the tooling or app-consent remediation.
The CLI writes a collector-only notice to stderr and records it as `partial_workload_notice` in the summary.

App-mode `auditex probe live --surface all` includes Exchange policy and DNS posture.
The standalone probe prints the Exchange session and Cloudflare resolver notices
before its reads; use `--surface` to limit probe surfaces.
`--probe-first` defers these two collectors to the collection phase, so it does not
repeat their PowerShell sessions or public lookups. A standalone app probe performs
the reads and a subsequent run repeats them. Added runtime depends on tenant size,
PowerShell connection time and public DNS/HTTPS latency; it has not been measured
in this offline validation. Allow time for a session per Exchange command and DNS
and HTTPS reads per domain rather than assuming Graph-only runtime.

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
2. Sign in with Azure CLI once (`az login`), or use the one-sign-in route below.
3. Run the generated probe command.
4. Review `live-readiness.json`, `audit-plan.json`, and `diagnostics.json`.
5. Add only the missing read permission or role justified by the probe.
6. Rerun probe before full collection.

App-only repeat runs:

```bash
auditex setup-guide m365 --mode app --auditor-profile app-readonly-full --collector-preset full --tenant-id contoso.onmicrosoft.com
```

The app registration must be customer-owned. Add only the listed Microsoft Graph application permissions and grant tenant-wide admin consent.

App-only runs authenticate with a client secret or a certificate, never both. The Teams admin policies (`teams_policy`, selected by the `global-reader` profile and the `full` preset) need the certificate: the Teams admin API refuses a secret-minted token, so a secret-only run records `teams_token_unavailable` for them. Upload the certificate's public part to the app registration, keep its private key (PEM or PFX) in a file only you can read (mode `600`) and pass the SHA-1 thumbprint the portal shows. An encrypted key takes its password from a file or an environment variable, never from the command line:

```bash
auditex run --tenant-name CONTOSO --tenant-id contoso.onmicrosoft.com --client-id <app-id> \
  --certificate-path ~/audit-keys/auditex-reader.pem --certificate-thumbprint <sha1-thumbprint> \
  --certificate-password-file ~/audit-keys/auditex-reader.pass --auditor-profile global-reader --collector-preset full
```

### Sign-ins per run (one sign-in rule)

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
| Guided `ga-setup-app` (saves the Microsoft 365 CLI app as the sign-in app) | At most 3 browser sign-ins: `az login` (skipped when Azure CLI is already signed in to the tenant), the Microsoft 365 CLI setup's own sign-in (it signs in as Azure CLI to create the app) and the `m365 login` check (skipped when the CLI is already signed in) |
| Power BI read-only admin API setting (Fabric admin portal) | 1 sign-in to the Fabric admin portal |
| Power Platform management-app registration (`Add-PowerAppsAccount`, `New-PowerAppManagementApp`) | 1 sign-in with the Power Apps administration module |
| Installing `pwsh` and `ExchangeOnlineManagement` | 0 |

Sign-in app for the one-sign-in delegated route, Exchange included: a public client with the **Mobile and
desktop applications** redirect URI `http://localhost`, the delegated Graph permissions the selected
collectors need, and the delegated `Exchange.Manage` permission on **Office 365 Exchange Online**, all with
admin consent; `ExchangeOnlineManagement` 3.1.0 or later. Details and sources are in the
[administrator permission guide](admin-permission-guide.md#exchange-online-in-a-delegated-run).

```bash
auditex guided-run --flow gr-audit --include-exchange --client-id <sign-in-app-id> --tenant-id contoso.onmicrosoft.com
```

Sign-ins for the certificate route, counted apart:

- Set-up (once): one administrator sign-in to the Microsoft Entra admin centre covers the app registration, the permissions and admin consent, the role assignment and the certificate upload. Creating the certificate and its key needs no sign-in.
- Audit (every run): no interactive sign-in. An app-only certificate run mints every service token (Microsoft Graph, Exchange Online, the Teams admin API and the optional Power BI and Power Platform resources) silently from the certificate.

Every app token then comes from the certificate; a saved `AZURE_CLIENT_SECRET` is ignored with a warning. `auditex setup-guide m365 --mode app` prints the same run as `app_run_certificate`, and `auditex guided-run --flow app-audit` takes the same four options. Set-up steps and the blast radius of the key credential are in the [administrator permission guide](admin-permission-guide.md#certificate-credential-for-app-only-runs).

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
