## RESULT M07-T17
status: done
summary: The lab trial tenant was rolled back on 21 Nov 2026 (16:26 to 17:25 GMT) from the rebuilt kit-7t, on G's "go" relayed by the manager (DEC-126 approval). Every kit-created and out-of-kit object is removed and read back absent; six setting or one-way leftovers are manual stops accepted under DEC-126 and DEC-144, all of which expire with the tenant. No passkey, code or password was needed; every sign-in was the operator account picked in the lab browser tab (DEC-090).

### Findings
rollback: complete
open-intents: 0
manual-stops: 6
manual-stops-unaccepted: 0
kit: kit-7t/dt-r7t-ro, MANIFEST 369 OK; dry run 116 planned, 0 failed, PLAN lines identical to the 15 Nov dry run (a fourth MANUAL was a Graph sign-in timeout on a by-name recheck)
99-rollback pass 1: 39 changed, 3 failed, stopped at the CA gate (the 05 journals of 22:37-22:43 are newer than the 10 journal, so the gate closed before the CA deletions)
99-rollback -Only 10-conditional-access: 10 changed, 0 failed (9 DT CA policies deleted, security defaults back on)
99-rollback pass 3: 112 changed, 4 failed, 3 manual (the expected three)
remove-m08b-pbi-access: removed (setting Disabled with no groups, group deleted and purged)
remove-m08a2-reader-cert: removed (key credential gone, key file deleted by the script)
rollback-extras: removed (guest Global Administrator assignment, guest deleted and purged; the MS.AAD.5.3 directory setting already read absent)
remove-auditex-fabric-operator-app: 5 of 5 steps done; the script's final filter read stops on a Graph 404 for a deleted principal (twice); absence proven by 8 read-only id reads
reader-app amendment consents: the 3 row 8 amendment permissions (DEC-068) deleted by id and read back absent so the reviewed removal script's journal check passes
remove-auditex-reader-app: 4 of 4 steps done; same final 404 read; absence proven by 7 read-only id reads; secret and env files moved to Trash
rollback-lab-setup: 5 removed (2 Cloud PC licences, provisioning policy, group, operator E5); no rerun needed for the policy
manual stop 1: row 2 organisation customisation, one-way, expires with the tenant (DEC-126, 15 Nov manager ruling)
manual stop 2: MS.SHAREPOINT.2.2 DefaultLinkPermission back to 0 refused (HTTP 400, twice); stays View, expires with the tenant (DEC-144)
manual stop 3: MS.SHAREPOINT.1.3 SharingDomainRestrictionMode back to 0 refused (HTTP 500, twice); stays AllowList, expires with the tenant (DEC-144)
manual stop 4: MS.AAD.5.5-5.7 defaultAppManagementPolicy restrictions, write accepted but not applied; stays restricted, expires with the tenant (DEC-144)
manual stop 5: MS.AAD.3.3 MicrosoftAuthenticator settings back refused (HTTP 400); stays stricter, expires with the tenant (DEC-144)
manual stop 6: row 7 Cloud PCs leave after their 7-day grace period (about 28 Nov 2026); stale device records expire with the tenant (DEC-126)
open intents: intent-0039a516 (MS.AAD.5.3 setting) reads absent; intent-8def1240 (MS.AAD.9.1 CA) was refused at create and the CA gate read no DT policy; intent-cb959c26 resolved made; none holds a live object
next: G passes the trial-cancellation brief to Codex (the manager relays it)
