## RESULT EXP-m07-first-sitting
status: done
summary: The smallest first sitting is the read-only dry run of 00-identity, with one browser sign-in to Microsoft Graph and no organisation enable step. The kit shows the dry run sends only reads, with one local exception (Q2). The one-way enable step sits before the Exchange script (20), not before 00. Q1 and Q4 rest on the README and the script text; the points that go beyond them are marked inferred.
changes: none (notes in .plan/work/EXP-m07-first-sitting/notes.md)
verification: none (documents and script text only; no script, PowerShell, network or sign-in)
risks: 1) The fix is proven only on the mock; the first live dry run is the real proof. 2) If Entra refuses the silent renewal, a browser may open and a re-sign-in as the same operator passes unnoticed (LIMITS section 7). 3) The handover's manifest hash differs from one quoted in ROUND-7R.md; compare at the manifest step.
questions_for_g: none

### Findings
**Q1. First sitting, in order (steps 1-2 are the tenant chat's, 3-6 are G's):**
1. Beforehand, the tenant chat has a filled-in config for this tenant and the operator account, with the Teams module pinned to 7.8.0. It runs the kit's `00-identity.ps1` from the frozen copy, with no apply option and no state folder. It checks the manifest first (Q4).
2. The script prints its header ending "DRY RUN (read-only...)", then asks Microsoft Graph to sign in.
3. G sees a browser window open on the Mac. He signs in as the trial's Global Administrator, the operator, and no other account. The kit refuses any other account (WRONG ACCOUNT).
4. G may see a consent screen for the "Microsoft Graph Command Line Tools" app. README says to consent as Global Administrator for the organisation. The scopes include write-capable ones (user, group, directory and role management, invite), which are granted but not used by a dry run.
5. That is one sign-in, for Graph only. Exchange, Teams, Security and Compliance, SharePoint and the Power platform are not touched. Inside the run the kit reconnects to Graph silently several times; no browser opens for those.
6. It worked when you see the SKU and licence-plan lines, then an `OK` line "Graph SDK retry handler context read back 0...", then `PLAN` and `OK` lines for users, groups and roles, and a final "== done: N OK, N planned, 0 changed, 0 failed". "0 changed" is correct.
7. A refusal looks like a red `GRAPH SESSION REFUSED: <what differed>`, a `WRONG ACCOUNT` or tenant stop, or "Refusing...". The script then sends nothing more. G does nothing but close the window. The tenant chat opens a fresh `pwsh -NoProfile` window and reruns the same command, and a repeat goes to G as a possible kit fault (DEC-014 precedent). A licence-plan stop prints the missing plan and the trial that brings it. A failed retry check on a dry run only prints a MANUAL line.

**Q2. Writes to the tenant: none, from the documents and script text; not run.**
- The header says "DRY RUN (read-only)".
- Every change goes through one gate (`_common.ps1`, the PLAN branch) that prints `PLAN` and returns when no apply option is given.
- The create calls (POST user, group, role, invitation) sit behind that gate (inferred from the script's structure, not each line traced).
- `Initialize-DtRun` creates the state folder and journal only under apply, so a dry run creates no journal or credentials file.
- Mock case `W7r-sdk-00-dry-run-reads-after-retry-check` models the dry run.
- Local trace: the SDK's own sign-in record under the home folder. A tenant-side trace may be the first-time consent grant (inferred, not stated).

**Q3. Later sittings.** Each script is dry run, then apply, then verify. Each run is its own process, so sign-ins do not carry over between runs. Graph is silent while the SDK record exists.
- 00, 05 and 10 (10 without enforce): Graph.
- 20: Exchange Online.
- 50: Exchange Online plus Security and Compliance, with a skip option for compliance.
- 30, 60 and 70: browser tokens, no module.
- 40: Teams.
- 90 and 99: all of them (99 signs in to every engine up front).
- The 9b connection check signs in to every service and then removes the Graph record. That makes `10 -Enforce` and 90's Graph sign-in browser sign-ins. Enforce is last, after 70, before 90.
- Gates: dry run, then apply with a state folder, then 90-verify next day (Teams provisioning gate, ScubaGear, then verify again). Apply stops on a failed write. After 00, G registers phishing-resistant methods by hand (step 2).
- The organisation enable step is Exchange's `Enable-OrganizationCustomization`, by hand, once, one-way, and rollback does not undo it. It comes before 20's apply (DEC-008 item 3). It is only needed for the sharing policy, and the 20 dry run reports it as MANUAL while it is pending (README step 5, `IsDehydrated`). It is not needed for 00.

**Q4. Preparable without G:**
- Check the frozen folder against the manifest. The handover gives the manifest's own hash, but it differs from one in ROUND-7R.md, so compare.
- Pins: PowerShell 7.4+, Graph module 2.25.0 exactly, Exchange module 3.7+, Teams 7.8.0, Python 3.11+ on PATH (00 stops on older), `dig`, OPA 1.20.2 and the ScubaGear checkout at the pinned commit (for step 11).
- Config: fill every placeholder (tenant id, domain, operator, and the SKU copied from the dry run's list).
- Before the first apply: TRIAL-FACTS checks 14, 30 and 31, which are read-only reads and do need a Graph sign-in.
- Note the trial end dates.
- Do not run the kit through any other route than `pwsh-guarded`.
