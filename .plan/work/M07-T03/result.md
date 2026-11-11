## RESULT M07-T03
status: done
summary: SPE_E5 needs only the configuration value the operator already set; the offline suite already runs with SPE_E5. Many extra trial SKUs truncate nothing, and no rows, verdicts or seat counts change. The real day-one blocker is AGENT_365: without it, 00-identity stops before anything is written, in the dry run and the real run alike, so every later step is blocked. No verdict depends on AGENT_365; MS.AAD.9.1 is expected met from Entra ID P2 alone. The three existing PIM assignment schedules can flip the expected verdict for MS.AAD.7.2.
changes: none in the kit; evidence written to .plan/work/M07-T03/notes.md
verification: none run (read-only review: grep, sed and one Python JSON read of kit-ro)
risks: one of the existing assignment schedules gives a principal outside the GA set a non-GA privileged role, so MS.AAD.7.2v1 becomes met where `not met` is expected; any SKU carrying an audited plan with a status value outside the schema stops 00, which the dry run shows; removing the AGENT_365 gate is a kit source change and reopens the offline gate.
questions_for_g: AGENT_365 (blocks step 1): obtain Agent 365 or E7 (spending, no kit change), or name MS.AAD.9.1 the gap (one kit source change, offline gate reruns)?
### Findings
1. No-Teams SKU, separate Teams trial, one E5 SKU:
- SKU match and seats: kit-ro/populate/00-identity.ps1:152-163,193-198 match the configured SKU and need exactly one Enabled copy. SPE_E5 passes with the config value alone (kit-ro/populate/tenant.config.example.json:9).
- TEAMS1: kit-ro/populate/_common.ps1:1800 is met by any usable SKU (union at :1828-1838), so it passes as is. The no-Teams wording at :1789,1800 and kit-ro/compare.py:272-289 is message text only; kit-ro/tools/test_compare.py:1432-1442 checks those strings, so leave them.
- Users: kit-ro/populate/00-identity.ps1:276-285 now gives the 16 users TEAMS1, which makes trial check 25 moot.
- Docs only: kit-ro/populate/README.md:53,59,70 step 0 (1),(2),(4); kit-ro/LICENCES.md:14-16,20-22; kit-ro/LIMITS.md:19,167,178; kit-ro/BLUEPRINT.md:410.
- Evidence: the mock harness already uses SPE_E5 (kit-ro/tools/mock-harness/Run-Mock.ps1:61, MockTenant.ps1:163-176).
2. Bounds and plans in several SKUs:
- No kit code assumes one SKU or a fixed plan count. Graph lists follow up to 200 pages (kit-ro/populate/_common.ps1:1935,1949-1981).
- Per-SKU checks are strict: kit-ro/populate/00-identity.ps1:151,173-176, kit-ro/populate/_common.ps1:1831-1835, kit-ro/populate/90-verify.ps1:240-241, against the status lists at kit-ro/populate/_schema.ps1:60,65. More SKUs means more strict reads; an unknown value stops 00 before any write.
- The 40-item bound belongs to Auditex, not the kit. kit-ro/LIMITS.md:30 and kit-ro/EXPECTED-VERDICTS.json:1119-1150 already record service_plans as `blocked oversize`, and extra SKUs keep it so.
- Plans in several SKUs change nothing: the licence check takes a union, the P2 test is count > 0 (kit-ro/populate/90-verify.ps1:236-246), and kit-ro/compare.py:279 covers the oracle side. Seats are counted on the configured SKU only.
3. AGENT_365:
- Where: required at kit-ro/populate/_common.ps1:1793, accepted only on SKU AGENT_365 or MICROSOFT_365_E7 (:1835), enforced at kit-ro/populate/00-identity.ps1:167-172. Also README step 0 (3), trial checks 26 and 27, and tests Cases-Round7i-W11a.ps1:230-232 and Cases-Round7l-W14a.ps1:189-192.
- Dry run and real run behave the same: sign-in and checks, the SKU read, plan-state and TEAMS1 lines printed (:139-150), then it stops with "LICENCES: ... AGENT_365". That is before the operator lookup and the preflight end (:227), so nothing is written.
- Verdicts: none. MS.AAD.9.1v1 is expected met, pinned oracle met, decided by the CA policy plus P2 (kit-ro/EXPECTED-VERDICTS.json:1120-1127; kit-ro/populate/10-conditional-access.ps1:138-140; kit-ro/populate/90-verify.ps1:304-306).
- Obtain the licence: no source change. Start or buy AGENT_365 or E7, wait for Success, assign the operator one seat.
- Name 9.1 the gap: delete kit-ro/populate/_common.ps1:1793; config cannot bypass it (:61-71). Then update the two mock cases and the docs. The 9.1 verdict expectation stays met.
4. Operator licence, two users, three PIM assignment schedules:
- Operator: step 0 (4) covers the missing E5 and Power BI plans: assign SPE_E5, with trial check 26 before and after. No script checks the operator's own licence; without it, steps 9-11 lose Power BI (kit-ro/compare.py:285-287).
- Two users: the size guard passes (kit-ro/populate/_common.ps1:3178-3187). Users are matched by exact dt.* UPN, and rollback refuses the operator and any UPN the kit does not create (kit-ro/populate/99-rollback.ps1:322-333).
- No mis-attribution: PIM lookups are per principal and role (kit-ro/populate/_common.ps1:2232-2260,2605). Rollback removes only the schedule its own journalled request created, and stops MANUAL if another schedule exists for the same principal and role (kit-ro/populate/99-rollback.ps1:241-268,335-339,350-353).
- Verdict risk: 90-verify counts every privileged principal (:480-492). A non-GA privileged role held outside the GA set flips 7.2 (kit-ro/BLUEPRINT.md:118).
5. Trial end:
- Nothing in the code computes or checks a trial length. The P365D and P180D PIM durations (kit-ro/populate/00-identity.ps1:341,358) outlast the trial, and rollback removes them.
- Before the end: steps 10-12, then `99-rollback.ps1 -Apply` while every service still answers (kit-ro/LIMITS.md:197). It needs tokens with at least 30 minutes left, the CA gate cleared, and slack for reruns (kit-ro/populate/99-rollback.ps1:16-23).
- Not undone by rollback: kit-ro/LIMITS.md:176-178 and kit-ro/populate/README.md:46,53.
- The separate Teams trial's paid-conversion risk no longer applies.
Configuration or operator steps only (accepted state stands):
1. Choose an AGENT_365 option. Obtaining it: start or buy AGENT_365 or E7, wait for Success, one operator seat.
2. Trial checks 14 and 31: record the principal and role of all three assignment schedules. If 7.2 would flip, you decide: remove them by hand (unjournalled) or accept the flip.
3. Step 0 (4): assign SPE_E5 to the operator, with trial check 26 before and after.
4. Skip step 0 (2), the Teams Enterprise trial; TEAMS1 on SPE_E5 meets it.
5. Confirm the second user is not one of the kit's dt.* UPNs.
6. Turn recurring billing Off on every trial; finish step 12 and the rollback before about 10 December.
Kit source changes (each reopens the offline gate):
1. Only if you name 9.1 the gap: delete kit-ro/populate/_common.ps1:1793, then update the two mock cases and the docs.
2. Only if the PIM read shows a flip and you keep those schedules: change the MS.AAD.7.2v1 expectation in EXPECTED-VERDICTS and BLUEPRINT.
3. Optional: replace the no-Teams wording in compare.py, the docs and the matching test.
