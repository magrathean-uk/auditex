# Auditex Setup Guide

Tenant administrators: every permission, role and setting the reader app needs is in [Reader app permissions](reader-app-permissions.md).

The audit machine runs Linux, macOS or WSL2 (Windows Subsystem for Linux 2). On native Windows Auditex stops with "Auditex needs Linux, macOS or WSL2; native Windows is not supported yet." Run it inside a WSL2 distribution.

## Default Exchange and public DNS collection

Runs with the `auto` or `global-reader` profile select `exchange_policy`
and `dns_posture` by default, as does the `full` preset. `app-readonly-full` also
includes both and adds `intune_depth`, `purview` and `ediscovery`; `ediscovery` needs
`eDiscovery.Read.All`, an [optional permission](reader-app-permissions.md#optional-collectors-not-part-of-the-grant)
of the reader app, and without it the run is partial. Every other preset (`config-only`, `identity-only`, `security-only`
and `power-platform`) replaces the profile defaults with its own list and omits
both, as does an explicit `--collectors` list; `--exclude` drops either one after
selection. Power Platform and Power BI remain opt-in.

A default run opens an Exchange Online PowerShell session for read-only
`Get-*` policy reads, with an Exchange token minted silently from the reader app's
certificate. Each fresh PowerShell process cannot inherit an operator's session.
Install `pwsh` and `ExchangeOnlineManagement`; the app's `Exchange.ManageAsApp`
permission and the Global Reader role are in [Reader app permissions](reader-app-permissions.md).
`Exchange.ManageAsApp` is a write-capable-named permission used read-only. Its blast radius is
tenant-wide Exchange policy visibility under Global Reader: read-only Get-* cmdlets
only; no mutating cmdlet is issued. A write-capable scope does not authorise tenant
writes. No additional Graph permission is introduced by these defaults.

Alert and DLP policies are read in a Security & Compliance (IPPS) session: a token
minted silently from the certificate for Microsoft Exchange Online Protection is passed to
`Connect-IPPSSession -AccessToken`. It needs `Exchange.ManageAsApp` on **Microsoft
Exchange Online Protection** (a second admin consent) with Global Reader, and
`ExchangeOnlineManagement` 3.8.0 or later; only read-only `Get-*` reads are issued
(see the [admin permission guide](admin-permission-guide.md#security--compliance-in-app-only-certificate-runs)).
A connect that fails stops the reads that follow: alert and DLP policies are then **not
assessed**, with reason `ipps_session_not_opened`. A session without the DLP cmdlets
skips the DLP reads as `dlp_licence_not_detected`. These section skips leave the
collector and run **ok** when other reads succeed; the gate passes with a named
limitation. The gap remains in coverage, collection gaps, the handoff, explorer and
AI context.

The run sends the tenant's domain names to the **DNS-over-HTTPS resolver**, a third party: the public
Cloudflare resolver, `https://cloudflare-dns.com/dns-query`, unless `--doh-endpoint URL`
or `AUDITEX_DOH_ENDPOINT` names another plain `https://` resolver. Only domain names,
no user data, are sent to that resolver; tell the tenant owner if that matters to them. SPF/DKIM/DMARC TXT lookups cover the tenant's Exchange
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
The guided `app-audit` flow keeps both default policy collectors and honours an explicitly
named or profile-selected `exchange` collector. Guided flows add no Exchange exclusion of their own.
Generated setup plans carry the permissions, tooling and collection notices of their command.
Generated probes retain the probe-only `windows365` surface.

Real Exchange/DNS failures leave dependent policies **not assessed**, with a clear
reason. DNS lookup failures mean unknown records, never absent records. If these
are the only failures, the run is **partial**, collection exits **0**, and the gate
blocks unless `--allow-partial` is supplied. Required collector/authentication
failures retain their non-zero exit behaviour. Missing tooling, consent and real
Exchange session failures retain the tooling or app-consent remediation.
The CLI writes a collector-only notice to stderr and records it as `partial_workload_notice` in the summary.

`auditex probe live --surface all` includes Exchange policy and DNS posture.
The standalone probe prints the Exchange session and DNS resolver notices
before its reads (it takes the resolver from `AUDITEX_DOH_ENDPOINT`); use `--surface` to limit probe surfaces.
`--probe-first` defers these two collectors to the collection phase, so it does not
repeat their PowerShell sessions or public lookups. A standalone probe performs
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

Google DNS posture (`google_dns_posture`, in the `core-security`, `mail` and `everything` presets) sends the
customer's verified domain names, and nothing else, to the public Cloudflare DNS-over-HTTPS resolver
(`https://cloudflare-dns.com/dns-query`), or to the resolver set in `AUDITEX_DOH_ENDPOINT`. The run prints this notice
on stderr before collection and writes it to `data-handling.json` and the report. Turn it off with
`--exclude google_dns_posture`, or use the `identity` or `collaboration` preset.

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

With an OAuth sign-in, Gmail delegates cannot be listed (Google allows that only under domain-wide delegation), so the Gmail surface is reported as partial and the report shows `delegates` as not read.

Each run checks the cached sign-in with Google. If the run needs scopes the cache was not granted, or the sign-in was revoked or has expired (OAuth clients in Testing status expire refresh tokens after 7 days), the browser sign-in opens again; you never need to delete the token cache by hand. If Google's sign-in service is briefly unavailable, a sign-in that is still in date is used as it is; an expired one stops the run with "run again later" and does not open the browser.

The service-account key must be an owner-only JSON file: `chmod 600 key.json`. Auditex refuses a key file that others can read, or a link, with `service_account_key_refused`.

Each collector signs in with only its own scopes. If the domain-wide delegation entry leaves a scope out, only the collectors that need it fail, and the capability matrix names the missing scope under `missing_permissions`. A collector that read some data but was refused one list is shown as partial (a role limit), not as a missing scope.

## Microsoft 365

Auditex audits Microsoft 365 one way: through the reader app, an app registration in the customer's own tenant that
signs in with a certificate. It never uses a client secret, a delegated permission or a sign-in window, so a run needs
no interactive sign-in. Everything the tenant administrator has to grant is in
[Reader app permissions](reader-app-permissions.md).

Preferred first pass:

```bash
auditex setup-guide m365 --auditor-profile global-reader --collector-preset full --tenant-id contoso.onmicrosoft.com
```

Admin flow:

1. The tenant administrator follows [Reader app permissions](reader-app-permissions.md) and hands over the application (client) ID, the tenant ID and the certificate thumbprint.
2. The operator keeps the certificate's private key (PEM or PFX) in a file only they can read (mode `600`). An encrypted key takes its password from a file or an environment variable, never from the command line.
3. Run the generated probe command.
4. Review `live-readiness.json`, `audit-plan.json`, and `diagnostics.json`.
5. Add only the missing read permission or role justified by the probe.
6. Rerun probe before full collection.

```bash
auditex run --tenant-name CONTOSO --tenant-id contoso.onmicrosoft.com --client-id <app-id> \
  --certificate-path ~/audit-keys/auditex-reader.pem --certificate-thumbprint <sha1-thumbprint> \
  --certificate-password-file ~/audit-keys/auditex-reader.pass --auditor-profile global-reader --collector-preset full
```

Auditex reads Microsoft Graph at `graph.microsoft.com`, so it audits commercial and GCC tenants; GCC High, DoD and
other sovereign clouds, whose Graph is elsewhere, are not supported. A certificate that Microsoft Entra refuses (the
thumbprint is not on the reader app, or the tenant ID is wrong) stops the run before collection with exit status 2 and
"A certificate app token could not be acquired. Check that the thumbprint is on the reader app registration and the
tenant ID is right." An explicit `--permission-hints` file that does not exist stops `auditex run`,
`azure-tenant-audit` and `auditex probe live` with exit status 2 (the probe before it writes any folder): "The
--permission-hints file was not found: <path>".

`auditex guided-run --flow app-audit` takes the same four options. `--mode app` on `auditex setup-guide m365` is accepted
for old scripts and changes nothing. The Teams admin policies (`teams_policy`, selected by the `global-reader` profile and
the `full` preset) need the certificate: the Teams admin API refuses any other token. A saved `AZURE_CLIENT_SECRET` is
ignored with a warning.

### Sign-ins

- Set-up (once): one administrator sign-in to the Microsoft Entra admin centre covers the app registration, the permissions and admin consent, the role assignment and the certificate upload. Creating the certificate and its key needs no sign-in. Power BI and Power Platform need one sign-in each to their admin portals (see [Reader app permissions](reader-app-permissions.md)).
- Audit (every run): no interactive sign-in. Every service token (Microsoft Graph, Exchange Online, Security & Compliance, the Teams admin API and the optional Power BI, Power Platform and SharePoint admin resources) is minted silently from the certificate; a service the app has no consent or setting for is recorded as a named coverage gap, never prompted for.

The blast radius of the key credential is in the [administrator permission guide](admin-permission-guide.md#certificate-credential).

Emergency access accounts: tell the Conditional Access check which accounts they are, so that it does not rely on inference. Pass `--break-glass-accounts` to `auditex run` or `azure-tenant-audit` (comma-separated object IDs, user principal names, display names or group names, or `@file` with one per line; an entry is looked up in the full user and group lists, and one that matches nothing, or a display name two accounts share, is reported as unresolved and not judged) or set `AUDITEX_BREAK_GLASS_ACCOUNTS` for any entry point; the option wins over the variable. List the group your policies exclude when the accounts are excluded through it (membership is read only for role-assignable groups). The same list tells the MFA and legacy-authentication checks which exclusions are acceptable: a Conditional Access policy for all users that excludes anything else (an administrator role, a guest type, a staff group) reads "enforced with exclusions" and fails the CIS and ScubaGear controls, so list the accounts even when you do not need the break-glass finding. The finding `ca.break_glass_exclusion_missing` then names each enabled policy that requires MFA or blocks and excludes none of the listed accounts. Without a list the accounts are inferred (names containing break glass or emergency access, and Global Administrator role holders), and the finding is rated medium at most.

```bash
auditex run --tenant-name CONTOSO --tenant-id contoso.onmicrosoft.com --client-id <app-id> \
  --certificate-path ~/audit-keys/auditex-reader.pem --certificate-thumbprint <sha1-thumbprint> \
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
