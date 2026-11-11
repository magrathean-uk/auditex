## RESULT M07-T05
status: done
summary: The cause is a regression in the MicrosoftTeams module, not in PowerShell or .NET. From 7.9.0, interactive sign-in passes MSAL a Windows-only GetConsoleWindow callback, which calls kernel32. One community report says 7.8.0 works on macOS on the same runtime.
Recommendation: pin 7.8.0. This is an operator step only. The fallback is a kit change that connects Teams with -AccessTokens minted by the kit's own browser flow.
Correction to the brief: ScubaGear step 11 never loads the Teams module. It reads Teams over REST with its own tokens, so this bug does not block it directly.
Correction to M07-T04: removing only 8.0.0 is not enough, because 7.9.0 fails too.
changes: .plan/work/M07-T05/notes.md (evidence, sources, option detail); kit not touched
verification: read kit-ro with grep and sed, plus the pinned ScubaGear checkout (read only). Web research used 3 searches and 5 fetches. No PowerShell was run, no sign-in, no tenant contact, nothing fetched was executed.
risks: The "7.8.0 works" report comes from a single community post, not from Microsoft. Whether 7.8.0's MSAL clashes with Graph 2.25.0 and EXO in one process (check L8) is still open. Under option B, the audience of the 48ac35b8 token is assumed until it is read live.
questions_for_g: none
### Findings
1. Kit
- Connect-DtTeams (kit-ro/populate/_common.ps1:3076-3085):
  - checks the version with Minimum 6.0.0, then imports MicrosoftTeams by name, so the newest installed version loads;
  - calls `Connect-MicrosoftTeams -TenantId <cfg> -UseDeviceAuthentication:$false`;
  - takes the account from the connect result and the tenant from Get-CsTenant, then runs Assert-DtIdentity, which refuses a missing or wrong value.
- Callers: 40-teams:35, 90-verify:940, 99-rollback:135, the README 9b check, and TRIAL-FACTS checks 6, 17, 18, 24 and L8. A mock case requires the device flag to be passed as false (Cases-Round7c-W4.ps1:391-398).
- On macOS the docs say only "PowerShell 7.4 or later (pwsh; macOS works)" and "MicrosoftTeams 6.0 or later" (README:41,44). The L1-L8 checks were never run live, and no Teams path is recorded as working on macOS.
- Step 11 (pinned ScubaGear 2446ad7, Connection.psm1:404-475) gets MSAL tokens with the Teams client 12128f48 and scope 48ac35b8-.../.default, then reads the REST API. The kit's override makes these sign-ins use the system browser.
- The kit already mints a Teams-client token (teamsapps) through its own PKCE loopback browser flow, with claim checks (_common.ps1:2642-2800).
2. Web sources
- Release notes (learn.microsoft.com/en-us/microsoftteams/teams-powershell-release-notes), 7.9.0: "Updates Connect-MicrosoftTeams cmdlet to use Web Account Manager (WAM)". The 8.0.2-preview entry lists no fix.
- Tech Community thread (techcommunity.microsoft.com/discussions/microsoftteams/teams-powershell-no-longer-works-on-macos---windows-only-dependency-after-7-9-0/4561845):
  - "MicrosoftTeams 7.9.0 and 8.0.0 fail; 7.8.0 works", on PowerShell 7.6.2 with .NET 10.0.8;
  - cause: "calls the Windows GetConsoleWindow function through [DllImport("kernel32.dll")]".
- Connect-MicrosoftTeams (learn.microsoft.com/en-us/powershell/module/microsoftteams/connect-microsoftteams):
  - -AccessTokens takes "MS Graph" and "Skype and Teams Tenant Admin API" tokens;
  - "pre-acquired access token sign-in flows are not affected" by WAM.
- MC1338817 (mc.merill.net/message/MC1338817) lists as unaffected: "Pre-acquired access tokens".
- Install page (learn.microsoft.com/en-us/microsoftteams/teams-powershell-install): "PowerShell 7.2 or later on all platforms".
- PowerShell Gallery, 7.8.0: Core and Desktop editions, no dependencies.
- What follows:
  - No macOS runtime has kernel32, so changing PowerShell or .NET cannot help.
  - Routes that avoid the call: 7.8.0 interactive; -AccessTokens; device code (excluded by the kit rules); certificate or managed identity (app-only, out of scope).
  - No source says whether -DisableWAM avoids the call.
3. Options, most promising first
- A. Pin 7.8.0 (operator step only)
  - Install it with -RequiredVersion and uninstall 7.9.0 and 8.0.0.
  - Keeps the sign-in rules and needs no source change.
  - Optional: the version config key M07-T04 proposed, plus a mock case.
  - Offline proof: the module itself cannot be proved offline. A browser tab opening (then cancelled) shows the kernel32 failure is gone without signing in.
- B. -AccessTokens (kit source change)
  - Add 'teamsgraph' and 'teamsadmin' token specs, client 12128f48, to Get-DtApiSpec and Get-DtToken.
  - Connect-DtTeams passes both tokens after the existing tid, upn, aud and exp checks, with enough token life for the run.
  - Files: _common.ps1, _schema.ps1, README, TRIAL-FACTS checks 6, 9 and L8.
  - Mock cases: replace the device-flag sweep for Teams; add wrong tid, upn and aud on each token, expired or short-lived tokens, and a connect failure.
  - Keeps the rules and adds token checks; reopens the gate (Tier A).
  - Offline proof: the suite plus a fake-JWT probe against the real 8.0.0 module with the network off.
- C. A different PowerShell or .NET runtime: does not help on its own (see 2).
- D. Windows PC or VM for 40-teams, 90-verify -Products TEAMS and 99-rollback -Only 40-teams
  - Keeps the rules: WAM is a browser broker, not device code.
  - No source change is intended (chmod is already skipped on Windows), but the kit has never run on Windows. Run the mock suite there first.
  - The state folder has to be shared between the two machines, which is the main risk.
- E. Teams as a gap (last)
  - Lost: populating the 14 MS.TEAMS policies, the Teams verify rows and rollback, checks 17, 18 and 24, the 9b Teams proof, and facts T12, T15, T19 and T25.
  - ScubaGear would still score the default state over REST, but with no kit verdict to compare.
4. Next experiment (nothing written to the tenant)
- In a fresh `pwsh -NoProfile`:
  - `Install-Module MicrosoftTeams -RequiredVersion 7.8.0 -Scope CurrentUser`
  - `Import-Module MicrosoftTeams -RequiredVersion 7.8.0`
  - `Connect-MicrosoftTeams -TenantId <TenantId>` (browser sign-in as the operator)
  - `(Get-CsTenant).TenantId`
  - `Get-CsTeamsMeetingPolicy -Identity Global | Select-Object Identity`
  - `Disconnect-MicrosoftTeams`
- Pass: a browser prompt, no kernel32 error, and the tenant id equals the config. Cancel any consent screen.
- If it passes, run L8 on 7.8.0 next. If it fails, take option B.
