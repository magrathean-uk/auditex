## RESULT REV-RAPP-sol
status: done
summary: verdict: approve
All five required changes from my first review are fixed in the create script. The only open part is the phase E command files, which still give the old secret path (S1).
No new blocking finding. The secret goes only to a new mode-600 file. Every write targets this app and comes after the journal's intent entry. The removal acts only on ids it has checked.
Detail: .plan/work/REV-RAPP-sol/recheck-2.md.
changes: .plan/work/REV-RAPP-sol/recheck-2.md and progress.md only; the scripts and the record are unchanged
verification: read-only. I read r0 and r1 in full, the r0-to-r1 diff (468 changed lines), the removal script and READER-APP-RECORD.md. File hashes match RAPP-fix/notes.md. day1/subscriptions.json has 28 trials, the earliest ending 2026-12-10T11:31:35Z. Nothing run, no sign-in, no network.
risks: the process-scoped sign-in with MaxRetry 0 is unproven live, but a failure there stops the run before any write; the default sign-in token carries every existing Graph CLI grant, the kit's write scopes included; the phase E files still give the old secret and env file paths
questions_for_g: none
### Findings
sol-1 fixed in the script: L87, L214-220 (folder 700, not a link, internal disk), L252-253 umask 077, L369 new file at mode 600 before the secret exists, L387-388 checked, L219 exit code checked. Open: phaseE/PHASE-E-COMMANDS.md L33-34 and L90 and phaseE/COMMANDS.md L15 still give the r0 path (S1).
sol-2 fixed: intent saved at L300-317 before the first POST at L321. Each step is journalled before and after it runs (L320-390), each consent at L338-342. Failure block at L398-411.
sol-3 fixed: dt-live/remove-auditex-reader-app.ps1 is new. Row 8 and the M07-T17 line are in READER-APP-RECORD.md L31 and L39, with the delegated grants recorded.
sol-4 fixed: expiry 2026-12-10T11:00:00Z at L72. The preflight recomputes the earliest trial end (L236-240), and L391 re-checks the expiry the tenant sets.
sol-5 fixed: role match uses the scriptblock form (L200-204, enabled, Application type, exactly one). try/finally with Disconnect at L210 and L414-423. Directory.Read.All dropped (L71).
point 2 secret: no path to a screen, log, transcript or other file. It lives only in $sec (L371) and is never output; L59-63 refuse -Debug and -Verbose; the journal never holds it; finally clears it. A running transcript cannot be detected, and the header says not to use one.
point 2 writes before intent: none. L258-297 are the sign-in and GETs only. By design, -AllowConsent adds its grant at sign-in (L263), before the journal exists (S2).
point 2 partial run: only a lost response leaves an object without its id, and its step stays started or failed. The removal adopts the service principal, role, secret or consent under narrow rules. For an app whose id was never journalled it refuses and says to remove it by hand, only on G's say.
point 2 sign-in: process scope, MaxRetry 0 set before the sign-in and re-read at L276. The token carries existing grants: populator-app.ps1 L39 gave the first two scopes and kit 00-identity L37-38 asks for the third. A missing scope refuses at L270-275, before any write.
point 2 role check: L357-364 reads every directory role assignment of the service principal, after the new one reads back and before the secret exists. It must be exactly one: Global Reader at '/'. For a new service principal that proves it is the only active role. PIM eligibility and Exchange role assignments are not read; none can exist yet.
point 3 removal: it removes only the journalled ids, each checked first: the role assignment, then the app (after its appId, name and credential checks), then the deleted-items entries. It refuses on any mismatch and prints the plan in both modes. It writes only with -Apply (L234), journals before the first DELETE (L243) and ends with status removed. No kit object can match.
point 4 record: row 8 matches the script's 25 permissions plus Exchange.ManageAsApp, Global Reader, the secret, the journal and the exclusions. The undo cell matches the removal script. One wording nit, see S3.
S1 (non-blocking, needed before E7): point SECRET_FILE and ENV_FILE in PHASE-E-COMMANDS.md to dt-live and update the expected E7 lines. Otherwise E8 fails on a missing file, or puts the env-file copy of the secret in the repository checkout.
S2 (non-blocking): with -AllowConsent, journal or print the consent path before L263, so a refusal at L264-297 still records the grant.
S3 (non-blocking): header L35-37 and row 8 name three scopes, but the default token carries every existing Graph CLI grant. Say so; the journal's tokenScopes list is the true record.
S4 (non-blocking): tell the operator to cancel any consent screen on the default path.
S5 (non-blocking): move the only-role count at L361 into the Wait-Graph read, so a lagging replica cannot stop the run with a false count.
S6 (non-blocking): optionally also read the service principal's PIM eligibility in the role check.
