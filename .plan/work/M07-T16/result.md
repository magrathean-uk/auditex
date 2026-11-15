## RESULT M07-T16
status: done
summary: Phase D ran on the lab trial tenant from the 7t live copy (round 7t: the 7s handover plus the 05 null-migration fix, DEC-085), every script dry run then apply, no -Enforce (DEC-084). All scripts ended 0 failed except the named items under Findings; the Fabric operator app was in FabricClientId before 60-powerbi. No create intent is open (52 intents, 52 resolved). Progress and timings: .plan/work/M07-T16/progress.md; logs in the internal records folder (dt-live/phaseD/sitting1).
changes: .plan/work/M07-T16/result.md, progress.md
verification: kit intent check over the state folder (Initialize-DtIntents logic): 52 intents, 52 closed, 0 open; per-script done lines in the sitting logs
risks: the strict Conditional Access policies stay report-only; Teams 5.1-5.3 org-wide app settings stay manual
questions_for_g: none
phase-d-kit: c3285015a186
phase-d: complete
open-intents: 0
writes-outside-kit: 2
### Findings
finding: 00-identity, 05, 10, 20, 30, 40, 50, 60, 70 applied (counts in progress.md); 99-rollback not run (M07-T17).
finding: out-of-kit writes: OUT-OF-KIT-WRITES row 12 (fallback guest GA, DEC-084) and row 13 (MS.AAD.3.3 diagnostic PATCH); each has a rollback line.
finding: MS.AAD.9.1: no agent SKU, the policy is not created (DEC-008 named gap); intent closed absent.
finding: MS.AAD.3.4: Microsoft retired the migration state; 05 reports manual, not applicable (DEC-085).
finding: MS.AAD.3.3: transient PATCH 400 on the first send; kit round for a retry (DEC-091).
finding: MS.AAD.5.3: Entra created the derived directory setting itself; intent resolved to it (DEC-091).
finding: MS.SECURITYSUITE.4.1: Set-ProtectionAlert by name finds no rule; the alert stays enabled (DEC-091).
finding: MS.TEAMS.5.1-5.3: org-wide app settings are portal-only (manual); the teamsapps read timed out on a missed relay.
finding: sign-ins: Connect-MicrosoftTeams opens the browser by absolute path; the lead relayed it with a process watcher (DEC-090).
