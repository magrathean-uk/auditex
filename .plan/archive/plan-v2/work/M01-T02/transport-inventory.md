# M01-T02 transport inventory

Scope: every outbound call site under `src/`. Line numbers verified at 340552f and unchanged at 462e13f (no `src/` change between them; the only `src/` change since the reviewed 27759ed is a docstring in `src/auditex/mcp_registry.py`, which makes no outbound call). Paths are relative to the repo root; line numbers are those of the call expression. Transport classes are the eight in `.plan/ARCHITECTURE.md` Interfaces ("Transport policy"):
1 tenant read; 2 token; 3 Graph `$batch` (GET-only sub-requests); 4 public lookup; 5 operator-configured sink; 6 parked model endpoint; 7 lab-only response path; 8 local subprocess.
Method for the sweep: ripgrep for `requests`, `Session`, `urllib`, `http.client`, `smtplib`, `socket`, `subprocess`, `Popen`, `os.system`, `googleapiclient`, `google.auth`, `msal`, then a read of each hit. No `httpx`, `aiohttp`, `os.system`, `os.exec*` or `webbrowser` use exists under `src/`. Tooling-only hits (`shutil.which`, `urllib.parse`, `session.get` on a dict) are excluded.

Result: 77 rows (A1-A24 with A4 and A20 split into a/b, B1-B28, C1-C22, D1), every one in exactly one class; no row is `unclassified`. Two definition gaps are resolved explicitly under "Interpretations" below and raised as questions (the frozen class text names only M365 transports and HTTP sinks).

Interpretations (need the orchestrator's DECISIONS.md entry to confirm):
- Google Workspace API reads (section B) are class 1 by extension: the class 1 text lists only M365 transports, but the Google provider is a tenant read under the same read-only product boundary. Recommend the entry amends class 1 to "tenant read (Microsoft Graph, Power BI, Power Platform, Teams admin REST, Google Workspace read APIs)".
- SMTP (A15) is class 5 by extension: class 5 names HTTP sinks only. It is not an HTTP verb and is kept out of the T03 HTTP allow-list; T03 needs no entry for it. Recommend the entry names SMTP in class 5.

## A. HTTP (`requests`, `urllib`) and SDK sockets

| # | file:line | library | method / verb | destination | gate | class |
|---|---|---|---|---|---|---|
| A1 | `src/azure_tenant_audit/graph.py:342` | requests Session.post | POST | Entra token endpoint built by `_token_url()` (graph.py:259-263) from the operator-configurable `auth.authority` (default login.microsoftonline.com; sovereign clouds by config), client-credentials grant for the Power BI, Power Platform, Exchange Online and Teams admin scopes (`app_token_for`; callers include `collectors/exchange_policy.py:105` and `collectors/teams_policy.py:87`) | none beyond the operator-set authority: no endpoint pinning, no host allow-list and no redirect disabling on this call; form body is the grant only | 2 |
| A2 | `src/azure_tenant_audit/graph.py:384` | requests Session.post | POST | same `_token_url()` authority, Graph client-credentials token (`_app_token`) | same as A1: operator-configured authority, not pinned, redirects not disabled | 2 |
| A3 | `src/azure_tenant_audit/graph.py:426` | msal PublicClientApplication (acquire_token_silent / interactive / device flow at 428-470) | POST (library-internal) | Entra authority `_authority()` (login.microsoftonline.com or configured sovereign cloud) | operator chooses interactive auth; msal only talks to the authority. Named operations: `acquire_token_silent` (graph.py:433) and `acquire_token_interactive` (graph.py:439) | 2 |
| A4a | `src/azure_tenant_audit/graph.py:520` (`_request`, GET dispatch) | requests Session.request | GET | Microsoft Graph (host-allow-listed) | `read_guard`-style check at graph.py:126-161: GET must carry no body, no method-override header (:135-142). It accepts any Graph GET path; it does not reject message or file content paths (see Limitations) | 1 |
| A4b | `src/azure_tenant_audit/graph.py:520` (same call expression, POST dispatch) | requests Session.request | POST to `/v1.0/$batch` or `/beta/$batch` only | Microsoft Graph `$batch` | graph.py:149-159: POST only to a `$batch` URL, plain JSON `requests` list, every inner method GET, relative inner paths, no inner body, no override header. It checks verbs and shape, not whether an inner path is a content path | 3 |
| A5 | `src/azure_tenant_audit/graph.py:633` | requests Session.request | GET (literal) | redirect hops from Graph (`_follow_redirects`), `allow_redirects=False`, bearer stripped for non-Graph hops | host check per hop against the allowed download hosts, method fixed to GET; follows any allowed-host URL Graph returns, so it cannot by itself prevent a content download | 1 |
| A6 | `src/azure_tenant_audit/graph.py:800` (`self._request("POST", f"{GRAPH_ROOT}/$batch", json={"requests": batch_requests})`) | requests Session.request via A4b | POST | Microsoft Graph `$batch` | the batch helper rejects any non-GET spec at graph.py:782-784 (`GraphError`), builds all inner entries with `"method": "GET"` (:788-796, body construction only), then A4b re-checks the shape | 3 |
| A7 | `src/azure_tenant_audit/power_bi.py:45` | requests Session.get | GET | `POWERBI_ROOT` (Power BI admin REST) | `same_origin` check, root pinned, token-in-path refusal, `allow_redirects=False` | 1 |
| A8 | `src/azure_tenant_audit/power_platform.py:67` | requests Session.request | method variable, but `ALLOWED_METHODS = {"GET"}` (power_platform.py:14, enforced at :56) | `POWER_PLATFORM_ROOT` (Power Platform admin REST) | method allow-list, same-origin check, root pinned, no redirects | 1 |
| A9 | `src/azure_tenant_audit/collectors/power_platform.py:199` | PowerPlatformClient.request (-> A8) | `method` argument, only value used is `TENANT_SETTINGS_METHOD = "GET"` (collectors/power_platform.py:16, call at :82) | Power Platform tenant settings | A8 allow-list refuses anything but GET | 1 |
| A10 | `src/azure_tenant_audit/adapters/teams_admin_rest.py:167` | requests.get | GET | Teams admin REST (host validated earlier in the module) | bearer token, `allow_redirects=False`, daemon-owned timeout and body cap | 1 |
| A11 | `src/azure_tenant_audit/dns_lookup.py:53` | requests Session.get | GET | `self.endpoint` (`DohClient.endpoint`, dns_lookup.py:45), default `DEFAULT_DOH_ENDPOINT` = `https://cloudflare-dns.com/dns-query`; configurable, not a fixed destination | no credentials; default redirect following is on (no `allow_redirects` argument) | 4 |
| A12 | `src/azure_tenant_audit/exposure_lookup.py:53` | requests Session.get (`RequestsHttpsFetcher`) | GET | `https://mta-sts.<domain>/.well-known/mta-sts.txt`, `https://login.microsoftonline.com/<domain>/v2.0/.well-known/openid-configuration` (callers at :104 and :135) | https only, no redirects, no credentials, 64 KiB cap | 4 |
| A13 | `src/auditex/notify.py:136` | requests.get | GET | operator-configured Jira search `/rest/api/3/search` (dedup lookup) | Jira env vars set; read-only lookup; fail-open | 5 |
| A14 | `src/auditex/notify.py:306` | requests.post | POST | operator-configured Teams or Slack webhook URL (`_send_webhook`) | webhook env var set; body passed through `_redact_value` and `_redact_string`; dry-run default in `send_notification` | 5 |
| A15 | `src/auditex/notify.py:359` | smtplib.SMTP | SMTP (EHLO, STARTTLS, AUTH, DATA) | operator-configured SMTP relay (`_send_smtp`) | SMTP env vars set; refuses a relay without STARTTLS (notify.py:362-370); not an HTTP verb; class 5 by the SMTP interpretation above | 5 |
| A16 | `src/auditex/notify.py:476` | requests.post | POST | operator-configured Jira `/rest/api/3/issue` | Jira env vars set; redacted payload; dry-run default | 5 |
| A17 | `src/auditex/notify.py:510` | requests.get | GET | operator-configured GitHub `/search/issues` (dedup lookup) | GitHub env vars set; read-only; fail-open | 5 |
| A18 | `src/auditex/notify.py:583` | requests.post | POST | operator-configured GitHub `/repos/<repo>/issues/<n>/comments` | GitHub env vars set; redacted payload | 5 |
| A19 | `src/auditex/notify.py:619` | requests.post | POST | operator-configured GitHub `/repos/<repo>/issues` | GitHub env vars set; redacted payload | 5 |
| A20a | `src/auditex/model_serving.py:197` (`Request(self.config.endpoint.rstrip("/") + path, data=data, headers=headers, method=method)`) | urllib.request.Request (construction; the method is a variable) | GET `/models` (caller :217) and POST `/chat/completions` (caller :259) | `ModelConfig.endpoint`, default `http://127.0.0.1:8080/v1`, or `AUDITEX_MODEL_ENDPOINT` | parked model layer; the T03 scan must see this construction site explicitly, because `method=` is where the verb is chosen | 6 |
| A20b | `src/auditex/model_serving.py:199` (`self._opener.open(request, ...)`, opener from `build_opener(ProxyHandler({}), _NoRedirect())`) | urllib opener | executes the A20a request | same as A20a | no proxy, no redirects, 4 MiB response cap, stderr warning when the host is not loopback (:181-182); off unless the operator runs the model path | 6 |
| A21 | `src/auditex/google_workspace/auth.py:122` | google-auth `credentials.refresh(Request())` (`google.auth.transport.requests`) | POST (library-internal) | `https://oauth2.googleapis.com/token`, fixed: `Credentials.from_authorized_user_file` (auth.py:120) goes through `from_authorized_user_info`, which always sets `token_uri=_GOOGLE_OAUTH2_TOKEN_ENDPOINT` and ignores any `token_uri` in the cache file; pinned by google-auth, not by the application | only on the operator's `oauth` auth mode with an expired cached token; no application-level host check | 2 |
| A22 | `src/auditex/google_workspace/auth.py:102` (service-account `Credentials.from_service_account_file`, then `with_subject` at :106; narrowed copies from `_scoped_credentials` client.py:121-129 and delegated copies from `user_delegated_credentials` auth.py:133, built at client.py:140) | google-auth service_account | POST (library-internal, JWT bearer grant) | the `token_uri` field of the operator-supplied key file (google-auth reads it from the key info); configurable, not pinned by the application | `domain-delegation` auth mode; scopes from `DEFAULT_GOOGLE_SCOPES` or the narrowed sets. The SDK refreshes inside `execute()`: once per credential copy on its first request, again whenever that copy's token has expired during a long run, and on a refresh-status response (401) | 2 |
| A23 | `src/auditex/google_workspace/auth.py:125` (flow constructed at :124 by `InstalledAppFlow.from_client_secrets_file`) | google_auth_oauthlib `InstalledAppFlow.run_local_server` | browser redirect, token exchange POST (library-internal) | the `auth_uri` and `token_uri` in the operator-supplied OAuth client file (Google's endpoints in a Google-issued file); configurable, not pinned by the application; plus a loopback listener on a random port | operator-run `oauth` first sign-in only; no application-level host check | 2 |
| A24 | lazy OAuth refresh: user credentials loaded at `src/auditex/google_workspace/auth.py:120` or acquired at :125, used by every `execute()` in section B (services built at client.py:118) | google-auth `google.oauth2.credentials.Credentials` via the SDK's authorised HTTP transport | POST (library-internal, refresh-token grant) | depends on how the credentials were obtained: cached credentials loaded at :120 refresh against the fixed `https://oauth2.googleapis.com/token` (google-auth override, as A21); newly acquired flow credentials from :125 refresh against the `token_uri` in the operator-supplied OAuth client file (as A23), configurable and not pinned by the application | `oauth` auth mode with a refresh token; independent of the explicit refresh at :122: the SDK refreshes before a request once the access token has expired (runs longer than the token lifetime) and on a refresh-status response (401) | 2 |

## B. Google API client (`googleapiclient`, class 1: tenant read via read methods)

All go through `_collect_pages` (client.py:158) or `_capture` and call only `list` or `get`. `build` is called at client.py:118 (service) and client.py:142 (per-user service); the imports at :115 and :139 are not call sites; both build services from the static discovery documents bundled with `google-api-python-client` 2.x (the default when no discovery URL is passed; `cache_discovery=False` only disables the file cache), so no discovery document fetch. Destination for every row: `*.googleapis.com` for the named API.

| # | file:line | library | method / verb | destination API | gate | class |
|---|---|---|---|---|---|---|
| B1 | `src/auditex/google_workspace/client.py:175` | googleapiclient | users.list | Admin SDK Directory | read-only Directory scope | 1 |
| B2 | `src/auditex/google_workspace/client.py:183` | googleapiclient | groups.list | Admin SDK Directory | read-only scope | 1 |
| B3 | `src/auditex/google_workspace/client.py:188` | googleapiclient | orgunits.list | Admin SDK Directory | read-only scope | 1 |
| B4 | `src/auditex/google_workspace/client.py:191` | googleapiclient | domains.list | Admin SDK Directory | read-only scope | 1 |
| B5 | `src/auditex/google_workspace/client.py:195` | googleapiclient | roles.list | Admin SDK Directory | read-only scope | 1 |
| B6 | `src/auditex/google_workspace/client.py:201` | googleapiclient | roleAssignments.list | Admin SDK Directory | read-only scope | 1 |
| B7 | `src/auditex/google_workspace/client.py:215` | googleapiclient | members.list | Admin SDK Directory | read-only scope | 1 |
| B8 | `src/auditex/google_workspace/client.py:222` | googleapiclient | users.aliases.list | Admin SDK Directory | read-only scope | 1 |
| B9 | `src/auditex/google_workspace/client.py:227` | googleapiclient | tokens.list | Admin SDK Directory (OAuth grants per user) | `admin.directory.user.security` scope (not `.readonly`; see risks) | 1 |
| B10 | `src/auditex/google_workspace/client.py:252` | googleapiclient | activities.list | Admin SDK Reports | `admin.reports.audit.readonly` | 1 |
| B11 | `src/auditex/google_workspace/client.py:260` | googleapiclient | alerts.list | Alert Center | `apps.alerts` scope (not read-only; see risks) | 1 |
| B12 | `src/auditex/google_workspace/client.py:289` | googleapiclient | users.settings.getAutoForwarding | Gmail settings (per user, delegated) | `gmail.settings.basic` (write-capable scope; see risks); settings only, no messages | 1 |
| B13 | `src/auditex/google_workspace/client.py:290` | googleapiclient | settings.filters.list | Gmail settings | same | 1 |
| B14 | `src/auditex/google_workspace/client.py:293` | googleapiclient | settings.forwardingAddresses.list | Gmail settings | same | 1 |
| B15 | `src/auditex/google_workspace/client.py:297` | googleapiclient | settings.sendAs.list | Gmail settings | same; the response carries each address's user-authored `signature` (see section G) | 1 |
| B16 | `src/auditex/google_workspace/client.py:298` | googleapiclient | settings.getImap | Gmail settings | same | 1 |
| B17 | `src/auditex/google_workspace/client.py:299` | googleapiclient | settings.getPop | Gmail settings | same | 1 |
| B18 | `src/auditex/google_workspace/client.py:300` | googleapiclient | settings.getVacation | Gmail settings | same; the response carries the vacation-responder subject and body (see section G) | 1 |
| B19 | `src/auditex/google_workspace/client.py:301` | googleapiclient | settings.delegates.list | Gmail settings | `gmail.settings.sharing` (write-capable scope; see risks) | 1 |
| B20 | `src/auditex/google_workspace/client.py:313` | googleapiclient | files.list | Drive v3 (metadata fields only; no `get_media` or `export` anywhere in the module) | `fields` limited to metadata (id, name, owners, permissions, links); no Drive scope in `DEFAULT_GOOGLE_SCOPES`, so the scope is supplied by the operator's credential; M01-T04 owns the scope check | 1 |
| B21 | `src/auditex/google_workspace/client.py:329` | googleapiclient | drives.list | Drive v3 | metadata listing; scope as B20 | 1 |
| B22 | `src/auditex/google_workspace/client.py:340` | googleapiclient | groups.get (Groups Settings) | Groups Settings API | read call; scope not in `DEFAULT_GOOGLE_SCOPES` (M01-T04 scope check) | 1 |
| B23 | `src/auditex/google_workspace/client.py:346` | googleapiclient | resources.calendars.list | Admin SDK Directory | read-only scope | 1 |
| B24 | `src/auditex/google_workspace/client.py:359` | googleapiclient | calendarList.list | Calendar API (calendar metadata) | read call; scope not in `DEFAULT_GOOGLE_SCOPES` (M01-T04 scope check) | 1 |
| B25 | `src/auditex/google_workspace/client.py:368` | googleapiclient | acl.list | Calendar API (sharing rules) | read call; scope as B24 | 1 |
| B26 | `src/auditex/google_workspace/client.py:385` | googleapiclient | policies.list | Cloud Identity Policy API (2-step verification) | isolated `POLICIES_SCOPE` token (auth.py:32) | 1 |
| B27 | `src/auditex/google_workspace/client.py:397` | googleapiclient | mobiledevices.list | Admin SDK Directory | read-only scope | 1 |
| B28 | `src/auditex/google_workspace/client.py:409` | googleapiclient | chromeosdevices.list | Admin SDK Directory | read-only scope | 1 |

## C. Subprocess launches (class 8 unless stated)

| # | file:line | library | verb / command | destination | gate | class |
|---|---|---|---|---|---|---|
| C1 | `src/azure_tenant_audit/auth_runtime.py:47` | subprocess.run | `az account get-access-token --resource https://graph.microsoft.com --output json` | local Azure CLI (the CLI itself talks to Entra) | fixed argv, timeout 120 | 8 |
| C2 | `src/azure_tenant_audit/adapters/powershell_graph.py:276` | subprocess.run | `pwsh -NoLogo -NoProfile -NonInteractive -Command <prepared>` | local PowerShell (Exchange Online, Graph cmdlets) | `read_guard.check_command` (called at powershell_graph.py:232 unless the command is a `VettedCommand`). The guard (read_guard.py:263-270) accepts the PowerShell language words, the `POWERSHELL_READ_COMMANDS` set and ANY `Get-<noun>` cmdlet; it is not a closed `api_inventory` allow-list. Exposure: `Get-Content`, `Get-MgUserMessage` and similar content-reading `Get-*` names pass the guard. The shipped collector commands are separately constrained by `api_inventory` (M01-T04 scope); the guard alone does not enforce that | 8 |
| C3 | `src/azure_tenant_audit/adapters/powershell_graph.py:55` (`_run_bounded`, called at :429) | subprocess.Popen | same pwsh argv from `_child_argv` | local PowerShell | same guard and same `Get-*` exposure as C2 | 8 |
| C4 | `src/azure_tenant_audit/adapters/m365_cli.py:161` | subprocess.run | `m365 ...` commands, `shell=False` | local CLI for Microsoft 365 | `read_guard.check_command` (m365_cli.py:128) | 8 |
| C5 | `src/azure_tenant_audit/evidence_db.py:535` | subprocess.run | `/usr/sbin/diskutil info -plist /System/Volumes/Data` | local system tool (is the data volume internal) | fixed argv, timeout 5 | 8 |
| C6 | `src/azure_tenant_audit/evidence_db.py:542` | subprocess.run | `/usr/sbin/diskutil apfs list -plist` (encryption state of the volume) | local system tool | fixed argv, timeout 5 | 8 |
| C7 | `src/azure_tenant_audit/probe.py:117` (`_subprocess_probe`; callers :193, :247, :328) | subprocess.run | probe toolchain checks: `az` version and account, `pwsh` module check, `m365 status --output json` | local CLIs | fixed argv built in `probe.py`; read-only checks | 8 |
| C8 | `src/azure_tenant_audit/probe.py:328` | subprocess.run via C7 | `pwsh ... Import-Module ExchangeOnlineManagement; Get-Command Get-MessageTrace` (only when `include_response`) | local PowerShell | `include_response` flag; availability check only, no tenant call | 8 |
| C9 | `src/auditex/auth.py:122` | subprocess.run | JSON sign-in status commands (`az`, `m365 status`) with `m365_subprocess_kwargs` | local sign-in CLIs | argv from fixed builders | 8 |
| C10 | `src/auditex/auth.py:149` | subprocess.run | `pwsh -NoLogo -NoProfile ...` Exchange module status check | local PowerShell | fixed script | 8 |
| C11 | `src/auditex/auth.py:201` | subprocess.run | `pwsh -Command "Install-Module ExchangeOnlineManagement -Scope CurrentUser -Force -AllowClobber"` | local PowerShell; PSGallery download (local install, not a tenant call) | explicit operator setup command; not in the audit path | 8 |
| C12 | `src/auditex/auth_runtime.py:72` (`_default_run_json_command`) | subprocess.run | JSON status commands and `bash select-python.sh` (call at :624) | local CLIs and a shipped script | fixed argv | 8 |
| C13 | `src/auditex/auth_runtime.py:103` | subprocess.run | `pwsh -NoLogo -NoProfile ...` Exchange module status check | local PowerShell | fixed script | 8 |
| C14 | `src/auditex/auth_runtime.py:150` | subprocess.run | interactive sign-in (`az login`, `m365 login`) | local sign-in CLIs | operator-initiated | 8 |
| C15 | `src/auditex/guided.py:127` | subprocess.run | `az login --tenant <id> --allow-no-subscriptions` | local Azure CLI | operator-initiated guided flow | 8 |
| C16 | `src/auditex/guided.py:207` | subprocess.run | interactive sign-in command | local sign-in CLIs | operator-initiated | 8 |
| C17 | `src/auditex/guided.py:295` | subprocess.run | `m365 login --authType browser --tenant <id> [--appId ...]` | local CLI for Microsoft 365 | operator-initiated | 8 |
| C18 | `src/auditex/auth.py:234` (lambda) | subprocess.run | interactive sign-in command | local sign-in CLIs | operator-initiated | 8 |
| C19 | `src/auditex/bootstrap.py:46` (`_run_json_command`) | subprocess.run | doctor and readiness JSON commands | local tools | fixed argv | 8 |
| C20 | `src/auditex/bootstrap.py:225` | subprocess.run | `bash <bootstrap script> [--exchange] [--pwsh] [--mcp]` | local installer script | operator runs `auditex setup` | 8 |
| C21 | `src/auditex/command_runner.py:109` | subprocess.run | runs `auditex` or `azure-tenant-audit` CLI argv built by `command_builders` for MCP tools | local child process of this product | argv from `command_builders`; output redaction; no shell | 8 |
| C22 | `src/auditex/auth_runtime.py:51` (`_default_json_command`, the default `AuthAdapters.json_command`, auth_runtime.py:170) | subprocess.run | JSON status and connection commands: `az account show --output json` (caller :194), `m365 status --output json` (:195), `m365 connection list --output json` (:196, :248) and `m365 connection use --name <name> --output json` (local connection selection, :255) | local Azure and Microsoft 365 CLIs | fixed argv from the callers; `shutil.which` pre-check; `m365_subprocess_kwargs`; local state only, no tenant call from this process beyond what the CLI does itself | 8 |

## D. Lab-only response path (class 7)

| # | file:line | library | verb | destination | gate | class |
|---|---|---|---|---|---|---|
| D1 | `src/azure_tenant_audit/response.py:437` (`adapter.run(command, ...)`) | adapter -> subprocess (rows C2/C3/C4 as the transport) | response actions; `message_trace` is read, every other action needs `--allow-write` (response.py:348) | tenant via PowerShell or m365 CLI | `AUDITEX_ENABLE_RESPONSE` (`features.response_enabled`; CLI gate cli.py:1467, MCP gate mcp_server.py:190 and :488), `--execute`, `--allow-write`, `--allow-lab-response` | 7 |

The sites C2, C3, C4 are class 8 when reached from the audit path and the same code is class 7 only when reached through D1; D1 is the one class-7 row, so no row carries two classes.

## E. Frozen non-GET allow-list (input to the DECISIONS.md entry and M01-T03)

Every non-GET site under `src/`, with its class and reason, as named operations, not module-wide allowances. Anything else that issues a non-GET method must fail the T03 test.

| site | method | class | reason |
|---|---|---|---|
| `src/azure_tenant_audit/graph.py:342` (A1) | POST | 2 | Entra client-credentials token for the Power BI, Power Platform, Exchange Online and Teams admin scopes |
| `src/azure_tenant_audit/graph.py:384` (A2) | POST | 2 | Entra client-credentials token for Graph |
| `src/azure_tenant_audit/graph.py:520` (A4b, via `_request`) | POST to `/v1.0/$batch` or `/beta/$batch` only | 3 | read batching, inner requests GET only, enforced at graph.py:149-159; the one caller is graph.py:800 (A6) |
| `src/azure_tenant_audit/graph.py:433` (`app.acquire_token_silent`) | POST (msal-internal) | 2 | silent refresh of the interactive Graph token |
| `src/azure_tenant_audit/graph.py:439` (`app.acquire_token_interactive`) | POST (msal-internal) | 2 | interactive sign-in token exchange |
| `src/auditex/google_workspace/auth.py:122` (`credentials.refresh(Request())`) | POST (google-auth-internal) | 2 | refresh of the cached OAuth user token |
| `src/auditex/google_workspace/auth.py:125` (`flow.run_local_server`) | POST (google_auth_oauthlib-internal) | 2 | first OAuth sign-in code exchange |
| lazy service-account refresh: credentials built at `src/auditex/google_workspace/auth.py:103-107`, narrowed or delegated by `client.py` `_scoped_credentials` and `user_delegated_credentials` (auth.py:133), refreshed by the SDK inside `execute()` of the calls in section B (A22) | POST (google-auth-internal, JWT bearer grant) | 2 | token exchange on the first request of each credential copy and on every later refresh (expiry during a long run, or a 401), all triggered by the `execute()` calls at client.py:175-409; destination is the key file's `token_uri`. There is no static call expression, so T03 identifies it by the credential construction sites, not by a module exemption |
| lazy OAuth refresh: credentials loaded at `src/auditex/google_workspace/auth.py:120` or acquired at :125, refreshed by the SDK inside `execute()` of the calls in section B (A24) | POST (google-auth-internal, refresh-token grant) | 2 | refresh of the OAuth user token whenever it expires mid-run or a request returns 401, independent of the explicit refresh at auth.py:122; destination is the fixed `https://oauth2.googleapis.com/token` for cached credentials (auth.py:120) and the OAuth client file's `token_uri` for newly acquired flow credentials (auth.py:125). Identified by the same construction sites, not by a module exemption |
| `src/auditex/notify.py:306` (A14) | POST | 5 | Teams and Slack webhook |
| `src/auditex/notify.py:476` (A16) | POST | 5 | Jira issue create |
| `src/auditex/notify.py:583` (A18) | POST | 5 | GitHub issue comment |
| `src/auditex/notify.py:619` (A19) | POST | 5 | GitHub issue create |
| `src/auditex/model_serving.py:197` Request construction (A20a) and :199 `open` (A20b); POST at caller :259 | POST (method is a variable at :197) | 6 | chat-completions on the parked model endpoint, loopback default; both stages recorded so the scan covers the `Request(method=...)` construction |

Not in this table, on purpose:
- SMTP (`notify.py:359`, A15) is not an HTTP verb; no T03 HTTP exception is needed. It is class 5 by the SMTP interpretation above.
- `src/azure_tenant_audit/power_platform.py:67` (A8) takes a method variable but is GET-only (`ALLOWED_METHODS = {"GET"}`, enforced at :56) and needs no non-GET exception. Its guard evidence stays in A8/A9; the T03 scan must treat the variable-method call as GET-only (resolve to that guard), not as an allowance.

## F. Notes for M01-T03 and M01-T04

- The T03 static scan has to understand `Session.request(method, ...)` with a variable method (A4, A8) and `Request(..., method=method)` (A20a); resolve them to the guards above rather than flag them.
- Limitations (facts for the T03 and T04 authors, not inventory rows): the Graph GET gate (graph.py:135-142) accepts any Graph path, the `$batch` gate (:149-159) checks verbs and shape but not inner-path content, and `_follow_redirects` (:633) follows any allowed download host. None of these alone prevents a message or file content read; `api_inventory` classifies calls after collection and the collector endpoints are what M01-T04 must scan. Likewise `read_guard` accepts arbitrary `Get-*` cmdlets (C2, C3), so the PowerShell read boundary rests on the collector commands being drawn from `api_inventory`, which T04 tests.
- Class 1 includes one wide-scope fact the criteria did not ask for: the Google default scopes include `admin.directory.user.security`, `apps.alerts`, `gmail.settings.basic` and `gmail.settings.sharing`, which are not read-only scopes. Every call made with them is a list or get (rows B9 to B19). This is flagged for M01-T04, whose test must accept them explicitly or the scope list must change.
- Row C11 downloads from PSGallery on operator request. It is not a tenant call and sits outside the audit path.
- Token endpoints (A1, A2, A3) use the operator-configured authority with no pinning and no redirect hardening. The Google token and consent endpoints for A22, A23 and flow-acquired A24 come from operator-supplied files (key file `token_uri`, OAuth client `auth_uri`/`token_uri`) with no application-level pinning; A21 and cache-loaded A24 use the fixed `https://oauth2.googleapis.com/token`, because google-auth overrides any cache-file `token_uri`. Recorded as facts, no code change in scope.
- No row is `unclassified`.

## G. Reads that receive user-authored body text (exposures for M01-T04)

These are class 1 reads of settings and policy endpoints, not message or file reads, but the response itself carries text a user or administrator wrote. For the first three rows minimisation strips the text after receipt, so it keeps the text out of raw and normalised output; it does not enforce the no-read boundary, because the bytes have already crossed the wire into process memory. The fourth row is not minimised at all: the text is retained. T04 must accept or remove each one explicitly.

| site | transport row | text received | handling after receipt |
|---|---|---|---|
| `src/auditex/google_workspace/client.py:300` `settings.getVacation` | B18 | vacation responder `responseSubject`, `responseBodyPlainText`, `responseBodyHtml` | client.py:302 `minimise_gmail_settings` (`VACATION_TEXT_FIELDS`, data_minimisation.py:24) |
| `src/auditex/google_workspace/client.py:297` `settings.sendAs.list` | B15 | per-address `signature` | client.py:302 `minimise_gmail_settings` (`SEND_AS_TEXT_FIELDS`, data_minimisation.py:25) |
| `src/azure_tenant_audit/collectors/mailbox_forwarding.py:255` `client.get_json("/users/<id>/mailboxSettings")` | A4a (Graph GET) | `automaticRepliesSetting.internalReplyMessage` and `externalReplyMessage` (automatic-reply bodies) | mailbox_forwarding.py:273 `minimise_mailbox_settings` (`AUTO_REPLY_TEXT_FIELDS`, data_minimisation.py:26) |
| `src/azure_tenant_audit/collectors/exchange_policy.py:126` `Get-TransportRule \| Select-Object ...,ApplyHtmlDisclaimerText,...` (run at exchange_policy.py:183) | C2/C3 (pwsh, Exchange Online) | `ApplyHtmlDisclaimerText`: the administrator-written HTML disclaimer appended to message bodies (a message-body template, not a message) | RETAINED, not stripped: `minimise_recipients` (exchange_policy.py:185; exchange_defender_commands.py:68) rewrites only `_RECIPIENT_KEYS` (SentTo, SentToMemberOf, ExceptIfSentTo, ExceptIfSentToMemberOf; :65), so the raw collector payload keeps the text, and `normalize.py:2107` copies it into the normalised `exchange_policy_object` as `apply_html_disclaimer_text`. Only the SCuBA adapter projection (`scuba_adapters_exchange.py:31-41`) drops it. T04 must accept the retention explicitly or drop the field from the `Select-Object` list |

Related, smaller exposure of the same kind (user-chosen words, not bodies): the transport-rule `PrependSubject` prefix from the same `exchange_policy.py:126` command (administrator-written, retained like the disclaimer); Graph inbox-rule predicates from `mailbox_forwarding.py:210` (`/mailFolders/inbox/messageRules`, `RULE_CONDITION_WORD_FIELDS`) and Gmail filter criteria from `client.py:290` (`GMAIL_FILTER_TEXT_FIELDS`); the last two are minimised after receipt in `data_minimisation.py`.
