## RESULT REV-M07-T11-opus
status: done
summary: verdict: ship
reviewed: 96ad252db64c, manifest check pass
Nothing blocking. The helper proves the session after every Set, refusals are sticky, and every Graph create is sent with MaxRetry 0 after the reconnect.
The 11 changed files and 1 new file stay within DEC-014 and the two 7q wording advisories. The advisories below are wording, test gaps and two edge cases that cannot occur on the live SDK or are unlikely there.
changes: none to the kit or repo; notes in .plan/work/REV-M07-T11-opus/notes.md and progress.md
verification: manifest check run inside dt-r7r-ro: pass (367 of 367 OK, file set equal, no write bit); dt-r7q-ro manifest check: pass (366 of 366); recursive diff of 7q against 7r: 11 changed, 1 new; no PowerShell or kit script run (the brief is read-only)
risks: 1) A browser sign-in as the same operator during a reconnect is still not detected. 2) The reset fix is proven only offline until the first live 00-identity dry run. 3) The full offline suite is still to run.
questions_for_g: none
### Findings
1. Helper: pass. The only Set-MgRequestContext is at _common.ps1:2014. The construct rule at tools/Test-KitConstructs.ps1:614-617 adds its finding directly, so no allow entry can waive it. Between the Set and the proof only Connect-MgGraph (same tenant and scopes, -UseDeviceCode:$false, :2016) and the local Get-MgContext run; no Graph request goes out. Assert-DtGraphUsable guards all 7 Invoke-MgGraphRequest call sites. Stop-DtGraphSession sets the refusal flag before it throws (:1986), so a caller that catches the refusal still cannot send.
   - Advisory: a blank field reads as '' rather than $null, so Compare-DtGraphSession (:1971) accepts '' against ''. Live this cannot happen: account and tenant are checked by Assert-DtIdentity, and auth type and credential type are enums. Fix: in Get-DtGraphSessionNow (:1959-1962) take .Value only when Status is Ok.
   - Advisory: if the put-back of 3 is refused after a create was sent (:2082), the refusal message includes Connect-MgGraph's error text. Get-DtCreateFailureKind (:1246) can match that text against its refusal list (for example "invalid"), and 00-identity.ps1:261 would then mark a user's password not-created although the user may exist. The intent stays open either way. Fix: return 'ambiguous' for "GRAPH SESSION REFUSED" before the refusal-text match.
2. Write safety: pass. Each create reads back MaxRetry 0 after the reconnect (:2032), and nothing runs between that read-back and the send. The put-back of 3 runs in the finally block, and the next create sets 0 again.
   - Advisory, inherited from 7q: non-create writes still go out at the default 3. These are PATCH, PUT and DELETE, plus three POSTs: assignLicense (00:286), members/$ref (00:314) and the rollback's PIM adminRemove (99:338).
3. Scope: pass.
   - No Exchange, Security and Compliance or Teams connect changed, nothing shares a session, and EXPECTED-VERDICTS is unchanged.
   - 99-rollback changes only the wording of :736-737; it makes no Set. That wording change is the 7q advisory fix.
   - The construct hashes still have the same 32 keys. Only the 00-identity and 99-rollback values changed.
   - The 3 allowlist entries removed were false positives that went stale once the bare Set left Send-DtGraphCreate. No wildcard.
4. Mock and tests: pass. The mock matches live facts 1, 2 and 4, and is consistent with fact 3. The HOME redirect is a harness-only alias, kit code never loads MockTenant.ps1, and Reset-Mock clears every new mock setting.
   - Checking the code by hand agrees with the author's claim that 14 of 14 kit cases fail on 7q. No baseline case, lint rule, allowance or expected verdict is weakened.
   - Advisory: no case covers an auth-type-only change, added scopes, a blank or null session field, or a refusal after the send whose error text matches the refusal list.
5. Documents: pass on the silent sign-in from the auth record and on Disconnect-MgGraph.
   - Advisory: LIMITS.md:224, populate/README.md:96 and TRIAL-FACTS.md:11 say a MaxRetry read-back failure gives GRAPH SESSION REFUSED and stops all further Graph requests. In the code it is NOT SENT for that create (0) or only a warning (3), and the run is not blocked. Fix the wording.
   - Advisory: README:96 says the reconnect "is silent from the record" without the caveat LIMITS section 7 gives.
   - Both 7q advisories are cleared: codex item 5 (README:9) and opus item 3 (99-rollback:736-737).
6. Hygiene and live risk: pass.
   - The changed files are ASCII only, with mock tenant and account names only, no paths or credentials.
   - The reconnect uses the configured tenant and already-consented scopes. It makes no tenant write, cannot reach another account or tenant unnoticed, and leaves no state the rollback misses.
   - I accept the stated limit (a browser sign-in as the same operator) because the account, tenant, auth type, credential type and scopes are still proven. Optional: refuse if the auth record changed during the reconnect.
   - Hygiene nit: tools/Test-KitConstructs.ps1:299-300, the $shapeLintAst comment now trails the new line.
