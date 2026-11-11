## RESULT M07-T04
status: done
summary: All three questions answered with kit-ro file:line references; the evidence and sign-in table are in .plan/work/M07-T04/notes.md.
Dehydration: the kit holds back only the sharing-policy write. A dehydration refusal of a create in 20 or 50 would most likely count as ambiguous. It would then leave an unresolved create intent that blocks every later writing script.
Teams: the kit imports the newest MicrosoftTeams installed, so it picks 8.0.0. Uninstalling 8.0.0 is enough and needs no source change.
Sign-ins: about 25 on day one as written. Graph and the REST tokens can be cut by operator steps alone; Exchange, Security & Compliance and Teams need a source change.
changes: .plan/work/M07-T04/notes.md only (work folder); the kit was not touched
verification: Python and grep reads of kit-ro only, no checks to run; no PowerShell, no sign-in, no tenant contact, no network
risks: Two points are unverified offline: whether this tenant refuses New-*Policy, New-TransportRule or Set-AdminAuditLogConfig while dehydrated, and whether the modules sign in again silently inside one process. "No preset rules" does not show whether the Built-In Protection rule exists; 7.1-7.3 depend on it (kit-ro/BLUEPRINT.md:424).
questions_for_g: Run Enable-OrganizationCustomization once by hand and wait for IsDehydrated False before the first 20/50 -Apply? It is a one-way tenant write that rollback does not undo. Recommended: yes.
### Findings
1. Exchange
- Dehydrated: 20 reads IsDehydrated in its preflight. It prints MANUAL for EXO.6.2 and skips only the sharing policy (kit-ro/populate/20-exchange.ps1:44-52,107). Every other write in 20 still runs (:84-125; mock Cases-Round7d-W6a.ps1:492-503).
- The kit never runs the cmdlet; README step 5 and checks 11/20 say to run it by hand (kit-ro/populate/README.md:75; kit-ro/TRIAL-FACTS.md:92,167).
- If dehydration refuses a modify, the script stops with FAILED and the earlier writes stay journalled, so they can be rolled back (kit-ro/populate/_common.ps1:1737-1743). In 50 the first write is Set-AdminAuditLogConfig, so a refusal there stops 50 before anything else is written (kit-ro/populate/50-defender.ps1:157).
- A refused create is worse. The dehydration message does not match the kit's list of refusal texts (_common.ps1:1197), so the create counts as ambiguous (:1211) and leaves an open intent (:1723-1742). That intent blocks every writing script (:154-160) until an absent resolution with two reads at least 600 s apart (:1525). The exposed creates are 20:122 and 50:186,203. No mock case feeds a dehydration refusal to a create or to Set-AdminAuditLogConfig.
- Audit log ingestion: 50 sets it to True first and accepts a delayed read-back as pending (50:152-161). Verify row 5.1 expects met (kit-ro/populate/90-verify.ps1:809; kit-ro/EXPECTED-VERDICTS.json:2705; TRIAL-FACTS.md:94,166).
- Presets: 50 only disables Standard and Strict and never creates one; an empty list writes nothing (50:121-131,168-176). The blueprint expects none enabled (EXPECTED-VERDICTS.json:2221).
- DLP: absent is expected; 50 creates DT-DLP-PII and its rule (50:248-278). Verify reads them at 90-verify.ps1:813-817; expected 3.1 met, 3.2 not met, 3.3 met, 3.4 not met (EXPECTED-VERDICTS.json:2518-2633).
- One accepted domain: the DT-* rules are scoped to every accepted domain (50:120,196,203). The config's CustomDomain must stay empty, or 20 stops in its preflight (20:73-76,147-148). The DNS rows are frozen from live DNS by 90-verify (90-verify.ps1:533-552).
- Check 12 gates nothing today (TRIAL-FACTS.md:93). Every read lists and matches the exact name (_common.ps1:2121-2133). The mock's error mode covers what this tenant does (Cases-Round7d-W6a.ps1:116-122,220). Nothing still relies on the list-everything behaviour.
2. MicrosoftTeams module
- README asks for "6.0 or later" and installs it with a bare install (README.md:44,56). pins.json has no Teams pin (_common.ps1:3088).
- Connect-DtTeams checks only that the newest installed version is 6.0.0 or later, then imports by name only (_common.ps1:1777-1782,3077-3078). There is no version check in 00-identity or TRIAL-FACTS (TRIAL-FACTS.md:158,231). 9b records the version and 99 only warns on a change (_common.ps1:3114-3157).
- So with 7.9.0 installed beside 8.0.0, the kit loads 8.0.0 in every fresh process. Pre-importing 7.9.0 helps only in a shared process (unverified).
- Configuration alone cannot select a version, because unknown config keys are dropped (_common.ps1:52,66).
- Smallest source change: an optional config key read by Connect-DtTeams, mirroring the Graph pin (_common.ps1:2975-2986). It touches _schema.ps1, tenant.config.example.json, README, the TRIAL-FACTS commands, Run-Mock.ps1:31-39 and one new case like Cases-Round7e-W7a.ps1:362.
- Pinning it in pins.json instead also means changing compare.py:468, which accepts only the three current keys, plus test_compare.py and the W7a-pins-json contract case (Cases-Round7e-W7a.ps1:337-341).
3. Sign-ins
- Each step runs in a fresh process (README.md:21-24). Day one as written needs about 25 sign-ins; separate dry runs add about 11 (table in notes.md).
- Next day needs about 14 (New-ScubaConfig 1, 90-verify 8, step 11 about 5). The rollback signs in to up to 8 services up front (kit-ro/populate/99-rollback.ps1:123-138).
- Graph reuses a cached context only when the tenant, the account and every requested scope match, and still runs the live /organization check (_common.ps1:2987-3014). The scope sets differ from script to script.
- Exchange, Security & Compliance and Teams always sign in again (_common.ps1:3050-3085), and the scripts disconnect at the end (20:178; 50:117,244,302; 40:210).
- REST tokens are cached per script only (_common.ps1:27,2819-2823). DT_TOKEN_* environment tokens are reused, each checked for tenant, account, audience and expiry (:2826-2831).
- Sharing a process does not bypass the intent block, because intents are on disk (_common.ps1:145).
- Risks of a shared process:
  - A pasted batch can run past a FAILED line.
  - Sessions from before -Enforce make the 9b check, 90 and 99 prove nothing.
  - An environment token can expire mid-rollback (99-rollback.ps1:163).
  - The scripts' disconnects also close the tenant session's own connections.
  - Step 11 must stay in a fresh process (README.md:82).
Configuration or operator steps only (accepted state stands):
1. Keep only MicrosoftTeams 7.9.0 installed (`-RequiredVersion 7.9.0`, uninstall 8.0.0). The 9b check, 40, 90 and 99 must all run on it.
2. Enable-OrganizationCustomization by hand, then IsDehydrated False, before the first 20/50 -Apply (your decision).
3. Leave CustomDomain empty. Read Get-ATPBuiltInProtectionRule and the Get-SafeLinksPolicy names before step 6 (T16).
4. One `pwsh -NoProfile` for steps 00-70, with Graph 2.25.0 pre-connected using the union of all 24 scopes. Run one script per command and read its done line before the next.
5. Mint DT_TOKEN_* once per REST API, again after a role change or -Enforce. Keep the 9b checks and step 11 in fresh processes.
6. Skip dry runs that inform no decision.
Kit source changes (each reopens the offline gate):
1. Name the MicrosoftTeams version through an optional config key read by Connect-DtTeams, plus a mock case.
2. Treat a dehydration refusal of a create as definite, and add mock cases for a dehydrated create and for Set-AdminAuditLogConfig.
3. Let Connect-DtExchange and Connect-DtTeams reuse an asserted session, and disconnect only what the script opened.
4. Optional: a REST token cache that lasts across scripts in one process, still claim-checked; correct the doc wording of check 12.
