## RESULT EXP-m07-stub
status: done
summary: Verdict partly. Microsoft.Graph.Authentication 2.25.0 can reach plain-http localhost via a custom environment plus a supplied access token (inferred, untested). The kit's Graph traffic is 7 Invoke-MgGraphRequest call sites. The 404 fault is catchable offline; the 7r request-context fault probably is not. Cost is a fraction of one round for the error-path slice. Details are in .plan/work/EXP-m07-stub/notes.md.
changes: none in the repo; wrote .plan/work/EXP-m07-stub/notes.md and progress.md
verification: none run (read-only look; no PowerShell, no import, no network)
risks: (1) whether a fake token fills Get-MgContext Account/TenantId/Scopes, which the kit's identity checks need, is unconfirmed; (2) the stub drifts from the live service unless recordings are dated and re-recorded; (3) a loosened guard unless it is a separate wrapper with OS-level loopback-only egress
questions_for_g: none
### Findings
1. Endpoint and auth (the module is on disk: manifest and help from files, DLL strings by `strings`; behaviour inferred, not run):
 - Route A, custom environment (works over plain http, inferred): Add-MgEnvironment and Set-MgEnvironment take -GraphEndpoint and -AzureADEndpoint, and Connect-MgGraph has -Environment [Microsoft.Graph.Authentication.dll-Help.xml]. The help examples use https only. Add-MgEnvironment writes to the SDK settings file; Set-MgEnvironment is documented as session-only.
 - Route B, access token (works over plain http, inferred): Connect-MgGraph -AccessToken takes a SecureString, with no Entra round trip [Help.xml]. Its parameter set has no -TenantId or -Scopes, so the kit's current Connect-MgGraph call cannot be used. Core has a UserProvidedAccessToken type [Microsoft.Graph.Authentication.Core.dll strings].
 - Route C, app-only against a stub authority (needs https and a trusted certificate): Azure.Identity refuses a non-https authority, which is the R7r-1 error [kit/dt-r7r-ro/TRIAL-FACTS.md]. Trusting a certificate on macOS is machine configuration, which is reserved.
 - Route D, HTTP proxy (needs https and a trusted CA): Invoke-MgGraphRequest has no -Proxy parameter in 2.25.0 [Help.xml]. The environment proxy variables would give a CONNECT tunnel, so a TLS-terminating proxy would be needed.
 - Route E, custom handler: none is documented (inferred). An absolute URI is host-checked against the environment endpoint ("InvokeGraphRequestInvalidHost" in the DLL strings).
2. Kit calls (from files):
 - Graph is 7 Invoke-MgGraphRequest sites, all in kit/dt-r7r-ro/populate/_common.ps1. Invoke-DtGraph has 28 callers: 00-identity 8, 05-entra-settings 14, 10-conditional-access 3, 99-rollback 3.
 - There are no typed Get-Mg* resource cmdlets in the kit. The session cmdlets are Connect-MgGraph (2 sites), Set-MgRequestContext (1), Get-MgContext, Get-MgRequestContext and Disconnect-MgGraph.
 - A Graph stub covers only those 7 sites. It does not cover Exchange and Security and Compliance (about 25 cmdlets) or Teams (about 15), which come from other modules.
 - SharePoint, Teams apps, Fabric, Power Platform and Power BI use plain Invoke-RestMethod (Invoke-DtRest). That is a cheaper, module-free stub target, and the PowerPlatformBaseUrl and PowerBIBaseUrl config keys already exist.
3. Stub needs:
 - A loopback listener answering by method, path and query. It returns Graph JSON, error bodies, Date, request-id and Retry-After headers, and an `@odata.nextLink` pointing back at the stub.
 - Recordings come from read-only GETs in a sitting, sanitised. Error shapes that cannot be provoked on demand (429, 503, 504, 401, 403) are written by hand and flagged synthetic.
 - Kit change: the 7 sites hard-code `https://graph.microsoft.com`, and the nextLink check requires that host over https [kit/dt-r7r-ro/populate/_common.ps1 around lines 1931 and 2126]. It needs one base-URL hook and a token-based sign-in branch, active only under the isolation proof used for DT_MOCK_HARNESS.
 - Guard (inferred design): today kit/pwsh-guarded empties PSModulePath and sets XDG_DATA_HOME to /var/empty, and its sha256 is checked by kit/check-suite-7l.sh. It would need a second wrapper with its own recorded sha256 that exposes only the 2.25.0 folder. That wrapper would run with a scratch HOME so the SDK's auth record and settings are untouched, and with loopback-only egress enforced by the OS, for example a sandbox profile. The Test-KitConstructs module allowlist stays as it is.
4. Verdict: partly (inferred).
 - Cost is a fraction of one kit round for the error-path slice, plus an independent review because it touches the guard and sign-in. Full-parity sign-in is not worth it.
 - Would have caught: the 404 fault, almost certainly (kit/dt-r7r-ro/TRIAL-FACTS.md, kit FAULT-7r-notfound record). The SDK builds that exception from the HTTP answer alone.
 - Would probably not have caught: the 7r request-context fault. It came from Azure.Identity rebuilding the interactive credential, and a supplied token has no authority to rebuild. A stub run could still show whether the fault is credential-specific.
 - Also testable for real: SDK retry on 429, 503 and 504, and MaxRetry 0 on the wire. Today the kit only reads the setting back, and says no wire proof is claimed.
