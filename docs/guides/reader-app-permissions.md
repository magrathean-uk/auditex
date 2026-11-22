# Reader App Permissions for the Tenant Administrator

Auditex audits Microsoft 365 one way: through a **reader app**, an app registration in your own tenant that
signs in with a **certificate**. This guide lists every permission, role and setting the reader app needs,
exactly as the Microsoft admin centres name them, why each is needed, how to check it worked and how to
remove all of it afterwards. Nothing outside this guide is needed, and nothing in it is optional for a
full audit unless it says so.

The reader app never uses a client secret, never uses a delegated permission and never opens a sign-in
window. Auditex only reads: it never changes a setting, never reads a message, file or chat, and never
writes to your tenant.

Who does what:

| Step | Who | Where |
| --- | --- | --- |
| 1 to 4 (app, API permissions, role, certificate) | Global Administrator | Microsoft Entra admin centre |
| 5 (Power BI) | Fabric Administrator or Global Administrator | Microsoft Entra admin centre, Fabric admin portal |
| 6 (Power Platform) | Power Platform Administrator or Global Administrator | PowerShell |
| 4 (private key) and 7 (check) | The person running Auditex | The audit machine |

## The whole grant at a glance

1. One app registration, single tenant, no redirect URI, no client secret, no delegated permission.
2. 30 application permissions with admin consent: 27 on Microsoft Graph, `Exchange.ManageAsApp` on Office 365
   Exchange Online, `Exchange.ManageAsApp` on Microsoft Exchange Online Protection and `Sites.FullControl.All`
   on SharePoint.
3. The **Global Reader** directory role on the app, and no other role.
4. One certificate: the public part on the app, the private key on the audit machine only.
5. Power BI: the setting **Service principals can access read-only admin APIs** enabled for one security group
   whose only member is the app.
6. Power Platform: the app registered as a Power Platform management application.

## Step 1: Register the app

1. In the Microsoft Entra admin centre open **App registrations** (type it in the search box at the top) and
   select **New registration**.
2. **Name**: for example `Auditex Reader`.
3. **Supported account types**: **Accounts in this organizational directory only** (single tenant).
4. **Redirect URI**: leave it empty. The reader app has no sign-in page.
5. Select **Register**. From the **Overview** page, note the **Application (client) ID** and the **Directory
   (tenant) ID**; the person running Auditex needs both.
6. Open **API permissions**. A new registration starts with the delegated permission **Microsoft Graph >
   User.Read**. Select **...** next to it, then **Remove permission**. The reader app has no delegated
   permission.
7. Open **Certificates & secrets > Client secrets** and check the list is empty. Do not add a secret.

## Step 2: Add the API permissions and grant admin consent

On the app, open **API permissions > Add a permission**. For each API below choose **Application
permissions** (never **Delegated permissions**), tick the permission and select **Add permissions**:

- **Microsoft Graph** is on the **Microsoft APIs** tab.
- **SharePoint** is on the **Microsoft APIs** tab (under **APIs my organization uses** it is called **Office 365
  SharePoint Online**).
- **Office 365 Exchange Online** and **Microsoft Exchange Online Protection** are on the **APIs my organization
  uses** tab: search for the name. Exchange.ManageAsApp is under the **Exchange** group.

When all 30 are listed, select **Grant admin consent for** your organisation and confirm. Every row must then
show **Type: Application** and **Status: Granted for** your organisation.

Every permission below is of type **Application** and needs **admin consent** (Microsoft requires admin consent
for every application permission). "Collectors" are the Auditex parts that use the permission; "SCuBA" names
the CISA SCuBA baseline policies that depend on it.

| API | Permission | Type | Admin consent | Why Auditex needs it | Collectors | SCuBA |
| --- | --- | --- | --- | --- | --- | --- |
| Microsoft Graph | `AccessReview.Read.All` | Application | Yes | Reads access review definitions. | identity_governance | none |
| Microsoft Graph | `Application.Read.All` | Application | Yes | Reads app registrations, enterprise apps, their credentials, owners and permission classifications. | identity, app_consent, app_credentials, directory_relationships | MS.AAD 5.2 |
| Microsoft Graph | `AuditLog.Read.All` | Application | Yes | Reads sign-in and directory audit logs and last sign-in times of users and apps. | identity, security, app_credentials | none |
| Microsoft Graph | `Channel.ReadBasic.All` | Application | Yes | Reads channel names of each team (no messages). | teams | none |
| Microsoft Graph | `DelegatedPermissionGrant.Read.All` | Application | Yes | Reads which delegated permissions users and admins granted to apps. | app_consent | none |
| Microsoft Graph | `DeviceManagementApps.Read.All` | Application | Yes | Reads Intune app protection policies. | intune, intune_depth | none |
| Microsoft Graph | `DeviceManagementConfiguration.Read.All` | Application | Yes | Reads Intune compliance and configuration policies, update rings and their assignments. | intune, intune_depth | none |
| Microsoft Graph | `DeviceManagementManagedDevices.Read.All` | Application | Yes | Reads managed device posture and Defender antivirus state. | intune | none |
| Microsoft Graph | `DeviceManagementScripts.Read.All` | Application | Yes | Reads Intune script names and settings (never the script body). | intune_depth | none |
| Microsoft Graph | `Directory.Read.All` | Application | Yes | Reads users, groups, roles, domains, organisation, licences and directory settings. | identity, app_consent, conditional_access, external_identity, consent_policy, domains_hybrid, licensing, identity_governance, dns_posture, app_credentials, directory_relationships | MS.AAD 5.3, 6.1, 7.1-7.3; licence checks |
| Microsoft Graph | `EntitlementManagement.Read.All` | Application | Yes | Reads access packages and catalogues. | identity_governance | none |
| Microsoft Graph | `Group.Read.All` | Application | Yes | Reads groups, their members and owners, and Teams-enabled groups. | identity, teams, directory_relationships | none |
| Microsoft Graph | `Organization.Read.All` | Application | Yes | Reads tenant details and licence plans. | licensing | MS.AAD 2.1, 2.3, 7.4-7.9, 9.1; MS.POWERBI licence check |
| Microsoft Graph | `Policy.Read.All` | Application | Yes | Reads Conditional Access, security defaults, authentication methods, authorisation, app management and cross-tenant access policies. | conditional_access, auth_methods, external_identity, consent_policy, cross_tenant_access | MS.AAD 1.1, 2.1, 2.3, 3.1-3.9, 5.1, 5.2, 5.5-5.7, 8.1, 8.2, 9.1 |
| Microsoft Graph | `Policy.Read.PermissionGrant` | Application | Yes | Reads the app consent (permission grant) policies. | consent_policy | none |
| Microsoft Graph | `ReportSettings.Read.All` | Application | Yes | Reads whether usage reports hide user names. | reports_usage | none |
| Microsoft Graph | `Reports.Read.All` | Application | Yes | Reads usage reports and MFA registration details. | auth_methods, reports_usage | none |
| Microsoft Graph | `RoleManagement.Read.Directory` | Application | Yes | Reads Privileged Identity Management role assignments, eligibilities and role settings. | identity_governance | MS.AAD 3.6, 7.4-7.9 |
| Microsoft Graph | `SecurityAlert.Read.All` | Application | Yes | Reads Microsoft Defender alerts. | defender | none |
| Microsoft Graph | `SecurityEvents.Read.All` | Application | Yes | Reads Microsoft Secure Score. | defender | none |
| Microsoft Graph | `SecurityIncident.Read.All` | Application | Yes | Reads Microsoft Defender incidents. | defender | none |
| Microsoft Graph | `ServiceHealth.Read.All` | Application | Yes | Reads Microsoft 365 service health. | service_health | none |
| Microsoft Graph | `ServiceMessage.Read.All` | Application | Yes | Reads message centre posts. | service_health | none |
| Microsoft Graph | `SharePointTenantSettings.Read.All` | Application | Yes | Reads SharePoint and OneDrive tenant sharing settings. | sharepoint, sharepoint_access, onedrive_posture | MS.SHAREPOINT 1.1, 1.3 |
| Microsoft Graph | `Sites.Read.All` | Application | Yes | Reads the site list (names, addresses, dates) and the SharePoint host name; never files or list items. | sharepoint, sharepoint_access, onedrive_posture, sharepoint_admin | MS.SHAREPOINT 1.2, 2.1, 2.2, 3.1-3.3 (host name) |
| Microsoft Graph | `Team.ReadBasic.All` | Application | Yes | Reads team names. | teams | none |
| Microsoft Graph | `User.Read.All` | Application | Yes | Reads user accounts. | identity | none |
| Office 365 Exchange Online | `Exchange.ManageAsApp` | Application | Yes | Opens Exchange Online PowerShell as the app for read-only `Get-` commands. | exchange_policy (and dns_posture, which reuses its accepted domains) | MS.EXO 1.1, 3.1, 5.1, 6.1, 6.2, 7.1, 13.1; MS.SECURITYSUITE 1.1-1.4, 2.1-2.4, 5.1, 6.1, 6.2, 7.1-7.3, 8.1, 8.2 |
| Microsoft Exchange Online Protection | `Exchange.ManageAsApp` | Application | Yes | Opens Security & Compliance PowerShell as the app for the alert and DLP policy reads. | exchange_policy | MS.SECURITYSUITE 3.1-3.4, 4.1 |
| SharePoint (Office 365 SharePoint Online) | `Sites.FullControl.All` | Application | Yes | Reads SharePoint and OneDrive sharing settings that only the SharePoint admin API carries. | sharepoint_admin | MS.SHAREPOINT 1.2, 2.1, 2.2, 3.1-3.3 |

APIs that get **no** permission:

- **Power BI Service**: add nothing, and never `Tenant.Read.All` or `Tenant.ReadWrite.All`. Microsoft refuses the
  read-only admin APIs to an app that holds a Power BI permission needing admin consent; access comes from step 5.
- **Skype and Teams Tenant Admin API**: add nothing. The Teams policy reads are allowed by the Global Reader role
  (step 3) and the certificate (step 4).
- **Power Platform**: add no API permission. Access comes from the registration in step 6.

### Exchange.ManageAsApp, twice

`Exchange.ManageAsApp` lets the app open a PowerShell session as itself. Its name sounds like management, but
the session can do only what the app's directory role allows, and the only role is Global Reader (step 3),
which is read-only. Microsoft publishes it once on each Exchange API: **Office 365 Exchange Online** for
Exchange Online PowerShell and **Microsoft Exchange Online Protection** for Security & Compliance PowerShell
(Microsoft Learn, "App-only authentication in Exchange Online PowerShell and Security & Compliance
PowerShell"), so the app needs both. Auditex runs only `Get-` commands from a fixed list and refuses anything
else before it is sent.

### Sites.FullControl.All, and why there is no read-only choice

SharePoint and OneDrive sharing settings such as the OneDrive sharing level, default link type and permission,
anonymous link expiry and email verification exist only in the SharePoint admin API
(`https://<tenant>-admin.sharepoint.com/_api/SPO.Tenant`). Microsoft Graph does not carry them. Microsoft
documents `Sites.FullControl.All` as the application permission that API requires and offers no read-only
permission for it (Microsoft Learn, "SharePoint admin APIs authentication and authorization"). SharePoint also
refuses app-only tokens made from a client secret, which is one reason the reader app uses a certificate.

**Auditex never writes with it.** It sends exactly one request with this permission, a `GET` of `SPO.Tenant`
with no body, keeps eight sharing settings from the answer and discards the rest. Its read guard refuses any
other method, address, query or body before anything is sent, and every request is listed in the run's
`api-inventory.json`. The permission itself, however, would let whoever holds the certificate change or delete
every site; see [If the private key is stolen](#if-the-private-key-is-stolen).

## Step 3: Assign the Global Reader role

1. In the Microsoft Entra admin centre open **Roles & admins** (search box at the top) and select the
   **Global Reader** role by its name.
2. Select **Add assignments**, search for the app by its name, select it and select **Add**. If you are asked
   for an assignment type, choose **Active** (an app cannot activate an eligible assignment).
3. Do not assign any other role.

Why: Exchange Online PowerShell, Security & Compliance PowerShell and the Teams admin API decide what the app
may see from its directory role, not from API permissions. Global Reader is a read-only role that Microsoft
lists for app-only Exchange and Security & Compliance PowerShell. Collectors: exchange_policy, teams_policy.
SCuBA: the MS.EXO and MS.SECURITYSUITE policies listed above and MS.TEAMS 1.1-1.7, 2.1-2.3, 4.1, 5.1-5.3.

## Step 4: Create and upload the certificate

The certificate is the reader app's only credential.

1. **Create it on the audit machine**, so the private key never travels. Use an RSA key of at least 2048 bits;
   a self-signed certificate is accepted. Set the expiry to the end of the engagement and no later. For
   example, with OpenSSL, for a 30-day engagement:

   ```sh
   umask 077
   openssl req -x509 -newkey rsa:3072 -sha256 -days 30 -nodes -subj "/CN=Auditex Reader" \
     -keyout auditex-reader.key.pem -out auditex-reader.cer.pem
   ```

   `auditex-reader.cer.pem` is the public certificate. `auditex-reader.key.pem` is the private key.
2. **Upload only the public certificate**: on the app go to **Certificates & secrets > Certificates > Upload
   certificate**, choose `auditex-reader.cer.pem` (a `.cer`, `.pem` or `.crt` file, never the key) and select
   **Add**. Copy the **Thumbprint** shown in the list: 40 letters and digits, the value Auditex asks for.
3. **Keep the private key on the audit machine only**, in a file only the person running Auditex can read
   (mode `600`), outside the folder Auditex writes its results to. Auditex refuses a key file that others can
   read, a link, or a file larger than 64 KiB. Never email it, copy it to a share or check it into a
   repository. If you protect the key with a password, keep the password in a separate owner-only file or an
   environment variable; Auditex takes it with `--certificate-password-file` or `--certificate-password-env`,
   never on the command line.
4. **Expiry**: when the certificate expires the reader app can no longer sign in, and Auditex reports that a
   certificate token could not be acquired. To continue, create a new certificate, upload it and delete the old one.

Collectors and SCuBA: every one, because Auditex signs every token request (Microsoft Graph, Exchange Online,
Security & Compliance, the Teams admin API, SharePoint admin, Power BI and Power Platform) with this
certificate.

## Step 5: Power BI read-only admin API access

1. In the Microsoft Entra admin centre open **Groups**, then **All groups > New group**. **Group type**: **Security**;
   **Group name**: for example `Auditex Reader Power BI`; **Membership type**: **Assigned**. Under **Members**
   add the reader app (search for its name) and nothing else. Select **Create**.
2. In the Fabric admin portal (formerly the Power BI admin portal) go to **Tenant settings > Admin API
   settings > Service principals can access read-only admin APIs**. Set it to **Enabled**, choose **Specific
   security groups**, add the group from 1 and select **Apply**. Changes can take up to 15 minutes.
3. Leave **Service principals can call Fabric public APIs** as it is: it is a different setting, and SCuBA
   policy MS.POWERBI 4.1 assesses it.

Why: the Power BI tenant settings are readable only through the Power BI admin API, and Microsoft opens that API
to an app only through this setting and group. It is read-only, but it shows the group's members everything the
Power BI admin APIs expose, including user names and report metadata; keep the app as the group's only member.
Collector: power_bi. SCuBA: MS.POWERBI 1.1, 2.1, 3.1, 4.1, 4.2, 5.1, 6.1, 7.1.

## Step 6: Power Platform management application

A Power Platform Administrator or Global Administrator registers the app once, signed in to Windows PowerShell
with the Power Apps administration module:

```powershell
Install-Module -Name Microsoft.PowerApps.Administration.PowerShell -Scope CurrentUser
Add-PowerAppsAccount -Endpoint prod -TenantID <tenant id>
New-PowerAppManagementApp -ApplicationId <application (client) id>
Get-PowerAppManagementApps
```

The last command must list the application ID. Microsoft documents the same registration as a REST call, made
with that administrator's own sign-in:
`PUT https://api.bap.microsoft.com/providers/Microsoft.BusinessAppPlatform/adminApplications/<application id>?api-version=2020-10-01`
with no body. An app cannot register itself.

Why: the Power Platform admin APIs (environments, data policies, tenant settings, tenant isolation) answer an
app only after this registration. It adds no Entra role and no API permission. Microsoft states that a registered
app is treated like a Power Platform Administrator and cannot be limited to reading, so register it just before
the audit and remove it straight after (see [Remove everything after the engagement](#remove-everything-after-the-engagement)).
Auditex sends only reads to these APIs. Collector: power_platform. SCuBA: MS.POWERPLATFORM 1.1, 1.2, 2.1, 2.2,
3.1, 5.1, 6.1 (MS.POWERPLATFORM 2.3 is not assessed by design).

## Step 7: Check it worked

The audit machine needs PowerShell 7 (`pwsh`) and the `ExchangeOnlineManagement` module 3.8.0 or later for the
Exchange and Security & Compliance reads; these are not tenant permissions. Then run one command with the IDs
from step 1 and the key and thumbprint from step 4. Replace every `<...>` placeholder, angle brackets included,
with your own value before you run it:

```sh
auditex run --tenant-name CONTOSO --tenant-id <directory (tenant) id> --client-id <application (client) id> \
  --certificate-path auditex-reader.key.pem --certificate-thumbprint <thumbprint> \
  --auditor-profile global-reader --plane full --probe-first \
  --collectors identity,app_consent,security,conditional_access,defender,service_health,auth_methods,reports_usage,external_identity,consent_policy,domains_hybrid,licensing,identity_governance,intune,sharepoint,sharepoint_access,onedrive_posture,teams,exchange_policy,dns_posture,app_credentials,directory_relationships,cross_tenant_access,intune_depth,teams_policy,power_bi,power_platform,sharepoint_admin
```

The last line printed names the run folder (`Output in ...`). Open `summary.md` there. A good result shows:

- the run went past sign-in: no certificate message, and the collector table lists the collectors with their
  item counts;
- `exchange_policy`, `teams_policy`, `power_bi`, `power_platform` and `sharepoint_admin` read `ok`;
- no line under **Coverage Gaps** names `insufficient_permissions`, `unauthenticated`, `session_not_connected`,
  `command_not_authenticated`, `ipps_session_not_opened`, `teams_token_unavailable` or
  `sharepoint_admin_access_denied`.

These coverage gaps are expected and are not permission problems: `sharepoint_access.sitePermissions`
(`site_permissions_app_only_not_read`) and `teams_policy` `messagingPolicies`, `appSetupPolicies` and
`tenantAppSettings` (`teams_powershell_not_supported`). A collector the preflight skips because the tenant does
not have that service (for example `defender` without the Defender alerts service) is also not a permission
problem.

If something is missing:

| What the run shows | Recheck |
| --- | --- |
| A certificate message before any collection (key file refused, key unreadable, thumbprint mismatch, certificate not valid, token not acquired) | Step 4: the key file mode, the thumbprint, the expiry, that the certificate was uploaded to this app |
| `insufficient_permissions` on a Microsoft Graph read | Step 2: the permission, and that admin consent shows **Granted** |
| `session_not_connected` or `command_not_authenticated` on `exchange_policy` | Step 2 (Office 365 Exchange Online), step 3, and the module version |
| `ipps_session_not_opened` | Step 2 (Microsoft Exchange Online Protection), step 3, and module 3.8.0 or later |
| `command_not_authenticated` on `teams_policy` | Step 3 |
| `sharepoint_admin_access_denied` | Step 2 (SharePoint `Sites.FullControl.All` and its consent) |
| `insufficient_permissions` on `power_bi` | Step 5: the setting, the group member, 15 minutes, and no Power BI API permission on the app |
| `insufficient_permissions` on `power_platform` | Step 6 |

## If the private key is stolen

Anyone who holds the private key file (and its password, if it has one) can sign in as the reader app from
anywhere, without any further check, until the certificate expires or is deleted from the app. They then hold
everything this guide grants: they can read the directory and the configuration the 27 Microsoft Graph
permissions cover, every file in every SharePoint site and OneDrive (`Sites.Read.All` and `Sites.FullControl.All`),
and Exchange, compliance and Teams configuration as Global Reader. Two grants go further than reading: `Sites.FullControl.All` lets them read, change and delete every SharePoint site and OneDrive, and while
the Power Platform registration exists they can administer Power Platform. Auditex never does either, but a
thief could.

So: keep the expiry short, keep the key in one owner-only file on the audit machine, remove the Power Platform
registration straight after the audit, and delete the certificate from the app as soon as the engagement ends.
If you think the key has leaked, delete the certificate from the app at once (**Certificates & secrets >
Certificates > Delete**); that stops every sign-in with it immediately.

## Remove everything after the engagement

In this order:

1. **Power Platform**: signed in as in step 6, run
   `Remove-PowerAppManagementApp -ApplicationId <application (client) id>` (REST: the same address as in step 6
   with `DELETE`); `Get-PowerAppManagementApps` must no longer list it. Do this before deleting the app.
2. **Power BI**: in the Fabric admin portal set **Service principals can access read-only admin APIs** back to
   **Disabled** (or, if other groups still need it, remove only the Auditex group from **Specific security
   groups**) and select **Apply**. Then in the Microsoft Entra admin centre open **Groups > All groups**, select
   the group and **Delete**.
3. **Global Reader**: in **Roles & admins** select **Global Reader**, select the app's assignment and **Remove
   assignments**.
4. **The app**: in **App registrations** open the app and select **Delete**. This removes its service
   principal, every API permission and admin consent, and the certificate. Then, on **App registrations >
   Deleted applications**, select it and **Delete permanently**.
5. **The audit machine**: delete the private key file and any password file.

To audit again later instead, keep the app but delete its certificate (and remove the Power Platform
registration); without a certificate nobody can sign in as it. Upload a new certificate before the next audit.

## What the reader app never needs

- No client secret, no delegated permission, no redirect URI and no user sign-in.
- No directory role other than Global Reader.
- No mail or chat permission (never `Mail.Read` or `Chat.Read.All`), no `Files.Read.All`, and no permission that
  can grant permissions (never `AppRoleAssignment.ReadWrite.All`). Two permissions in this guide do allow reading
  documents: `Sites.Read.All` and `Sites.FullControl.All` let the app read the files in every SharePoint site and
  OneDrive. Microsoft offers no narrower permission for the site and SharePoint admin settings Auditex reads.
  Auditex itself never opens or downloads a file or a message; it reads settings, permissions and counts only.
- No Power BI API permission (never `Tenant.Read.All`).
- Nothing outside steps 1 to 6.

## Optional collectors (not part of the grant)

A full audit does not use these collectors and does not need their permissions. Add a permission only if the
person running Auditex plans to select that collector with `--collectors`, and remove it afterwards with the app.

| Collector | Adds | API | Type | Admin consent | Why |
| --- | --- | --- | --- | --- | --- |
| mailbox_forwarding | `MailboxSettings.Read` | Microsoft Graph | Application | Yes | Reads the inbox rules and mailbox settings of every mailbox (no messages). The full audit reads mailbox forwarding through Exchange Online instead. |
| mailbox_forwarding (inbox-rule move targets) | `MailboxFolder.Read.All` | Microsoft Graph | Application | Yes | Reads mailbox folder metadata (folder IDs and names, never a message) to tell whether an inbox rule moves mail to a folder that hides it (Junk Email, Deleted Items, Archive, Conversation History, RSS Feeds). Without it those rules are reported as not assessed, never as clean. |
| identity_protection | `IdentityRiskyUser.Read.All` | Microsoft Graph | Application | Yes | Counts risky users (Microsoft Entra ID P2). |
| defender_cloud_apps | `ConsentRequest.Read.All` | Microsoft Graph | Application | Yes | Reads app consent requests. |
| ediscovery | `eDiscovery.Read.All` | Microsoft Graph | Application | Yes | Reads eDiscovery cases with their searches and operations. |

`copilot_governance` adds nothing to grant: its usage counts use `Reports.Read.All`, already granted, and its
limited-mode read needs `CopilotSettings-LimitedMode.Read`, which Microsoft publishes only as a delegated
permission. The reader app never takes a delegated permission, so that one read is recorded as a coverage gap.

Related reading: the exact calls behind each permission are in the [API call catalogue](../reference/api-call-catalog.md).
