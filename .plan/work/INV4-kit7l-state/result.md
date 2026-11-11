## RESULT INV4-kit7l-state
status: done
summary: Round 7l ran as 7l, 7l2 to 7l6. The last gate on any snapshot (gate 21, on dt-r7l5-ro) was DO NOT SHIP with 0 high, 0 medium, 4 low; 7l6 claims all four fixed but no gate has run on it. The live kit differs from dt-r7l5-ro in 21 files. The full 7l6 suite and gate 22 have not run. 7m and 7n are separate copies; day one depends on 7m, not on 7n or 7o (inferred).
changes: none
verification: 3 read-only shell commands passed (ls/wc of reviews and records; ls of ship/tree/run/kit; diff -rq live kit vs dt-r7l5-ro, plus grep of chk-r7l5/run.sh and find|wc of kit-7m and kit-7n). Read and Grep calls on named files. No tests, Run-Mock, PowerShell or tenant contact.
risks: Live kit has never been gated as it stands. The 7m3 merge base is unknown, which blocks 7m integration. No full Run-Mock with rc 0 is recorded on any state after 5 Nov.
questions_for_g: Is day one attended (op token exposure accepted, no 1Password SDK) or unattended (service account, needs 7o)? The records say both.
### Findings
Aliases: kit/ = development-kit/20261031-dummy-tenant; ship/ = development-kit/20261027-ship-plan; rec/ = records/auditex.

1. exists
- kit/populate/: _common.ps1, _schema.ps1, scripts 00 to 99, README.md.
- kit/tools/: mock-harness/, Test-KitConstructs.ps1, Test-ShapeLint.ps1, test_compare.py, make_blueprint.py, derive_coverage.py.
- kit/tools/mock-harness/Cases-Round7l-W14a.ps1, Cases-Round7l-W14b.ps1, Cases-Round7l2-W16a/W16b.ps1, Cases-Round7l3-W17a/W17b.ps1, Cases-Round7l4-W19a/W19b.ps1, Cases-Round7l5-W20a.ps1. No 7l6 case file; 7l6 edited existing case files.
- kit/reviews/dummy-tenant-fix7l-w14a-last.md, fix7l-w14b-last.md, fix7l2-w16a/w16b-last.md, fix7l3-w17a/w17b-last.md, fix7l4-w19a/w19b-last.md, fix7l5-w20a-last.md, fix7l6-w21a-last.md.
- ship/tree/run/kit/gate17b-last.md, gate18-last.md, gate19-last.md, gate20-last.md, gate21-last.md, gate7m-last.md; briefs brief-w14a.md to brief-w21a.md.
- ship/tree/run/kit/kit-7m (323 files) and kit-7n (310 files); 7o is design only (ship/tree/run/kit/d7o-last.md, d7o-brief-sent.md).
- rec/development-20261107/LEAD-HANDOVER-20261107-B.md (32 lines), KIT-7M-PROVENANCE-BLOCKER.md (11 lines); rec/planning-20261107/DEVELOPMENT-PLAN.md (102 lines).
- ship/PLAN-SHIP.md (500 lines; last entry 5 Nov 22:11 GMT); ship/next-round-7l-items.md (60 lines).

2. works
- D1 (intent before send): kit/populate/_common.ps1:1557-1602; send follows the add at 1602. Mock cases Cases-Round7l-W14a.ps1:61 and :98 (Grep).
- D2 (resolve before create or modify): 16 physical sites (kit/reviews/dummy-tenant-fix7l-w14a-last.md:5); mock case per site at Cases-Round7l-W14a.ps1:79.
- D3 (CA gate honours intents): kit/populate/99-rollback.ps1:674 and :767 (Grep); mock case Cases-Round7l-W14a.ps1:101.
- D4 (429 is a refusal): kit/populate/_common.ps1:1628-1635 (Graph only, 4 attempts, each recorded) and :1712; mock cases Cases-Round7l-W14a.ps1:215 and :221-224.
- Snapshot diff: `diff -rq` shows 21 differing files, excluding reviews/ (live kit vs ship/tree/run/kit/dt-r7l5-ro).
- chk-r7l5/run.sh has one line that matters: line 3, `waitload ... || exit 3` (grep).
- Not verified by me: that any mock case passes.

3. broken
- Full Run-Mock never rc 0 on a recorded final state. 7l5: killed rc 143 at W13b with 8 assertion failures (rec/planning-20261107/DEVELOPMENT-PLAN.md:35). 7l6: rc 143 at W13b, no suite summary (kit/reviews/dummy-tenant-fix7l6-w21a-last.md:27).
- chk-r7l5/run.sh has no ASSERT FAILED, THREW or Run-Mock rc propagation; the W21a wrapper reported rc 0 on a killed run.
- Five loopback-dependent assertions fail in the sandbox (W10a, W12a x3, W13a): kit/reviews/dummy-tenant-fix7l-w14a-last.md:52.
- Gate 21 open lows, claimed fixed in 7l6, not gated: ship/tree/run/kit/gate21-last.md:3, :5, :7, :9.
- No dt-r7l6* snapshot exists under ship/tree/run/kit (ls).

4. dead candidates
- kit/run/kit/protocol/{before, intent-closure-before, repair-r1-before, repair-r2-before}/ contains nested copies, including run-tests.sh and Cases-Round7l-W14a.ps1. Evidence: Grep of `TODO|FIXME|XXX|dt-r7l*|kit-7[mn]|dt-7[mn]` over kit/ excluding reviews/ gave 13 hits in 12 files; four are in run/kit/protocol (inferred dead).
- Superseded snapshots in ship/tree/run/kit: dt-r7l-a, dt-r7l-a2, dt-r7l2 to dt-r7l5 (and -ro), dt-r7m(-ro), dt-7m-a-ro, dt-7m-b(-ro), dt-7n-a-ro, chk-a, chk-a2, chk-7m-b. Still named as evidence in the ledgers; the rg count did not isolate their references (inferred).
- Abandoned TODOs: none confirmed.

5. contradictions
- Plan says "Defer every live-dependent task" (rec/planning-20261107/DEVELOPMENT-PLAN.md:47) and "Keep 7m, 7n, 7o behind 7l" (:63). PLAN-SHIP 4 Nov 20:28 lifted the no-sign-in rule for the playground; 5 Nov 14:04 approved the 7m design.
- Unattended day one: PLAN-SHIP 4 Nov 21:56 says the service account "runs unattended"; 5 Nov 14:03 says op token exposure is accepted for attended day one only and unattended needs 7o.
- Gate 17 ran on dt-r7m-ro (PLAN-SHIP 5 Nov 07:29), but KIT-7M-PROVENANCE-BLOCKER.md:5 names dt-r7m-ro as the 7m baseline and dt-r7l-ro as the 7l baseline.
- Plan requires Auditex at 64817c8 (kit/reviews/dummy-tenant-fix7l-w14a-last.md:35); recorded checkouts were 0ccdef08, 872633e, f32448c3, 22d64f2, b591772, e62cc486, 061e657c, 594b86b (fix7l4-w19b-last.md:13, fix7l5-w20a-last.md:15, fix7l6-w21a-last.md:31).
- "D" labels collide: next-round-7l-items.md:9-17 (D1-D4), DECISIONS D1-D8 (DEVELOPMENT-PLAN.md:9), kit D5-D7 and D6' (PLAN-SHIP 5 Nov 11:04, 15:32).
- kit/populate/_common.ps1:1208-1209 classifies 429 as ambiguous for generic creates; D4 holds only through the Graph branch at :1712 (inferred intentional).

6. open questions
- Is the live kit only 7l5 plus 7l6? Compare the 21 diffs with the W21a edit list (kit/reviews/dummy-tenant-fix7l6-w21a-last.md:5-19). Unexplained: Cases-Round7.ps1, Cases-Round7b.ps1, Cases-Round7bW3.ps1, Cases-Round7e-W7a.ps1, Cases-Round7h-W10a.ps1, Cases-Round7i-W11a.ps1, Cases-Round7j-W12a.ps1, Cases-Round7k-W13a.ps1, Cases-Round7l4-W19a.ps1, Cases-Round7l5-W20a.ps1, Run-Mock.ps1, TRIAL-FACTS.md; kit/run/ is live-only.
- Which environment permits loopback listeners for the five cases? Settle by running the W14a follow-up command (ship/tree/run/kit/w14a-scratch/follow-up-1/) outside this sandbox.
- Who runs the 7l6 suite and gate 22? Plan row 8 (rec/planning-20261107/DEVELOPMENT-PLAN.md:63) assigns it but names no owner.
- 7m3 merge base: KIT-7M-PROVENANCE-BLOCKER.md says G has no answer; ROOT-KIT-PROVENANCE-USER-ANSWER.md was not opened.
- Teams and E5 trial length: fix7l2-w16b-last.md (W16b) cites BLUEPRINT.md:399 as "one month"; W14a says LICENCES.md:161 gives no fixed Teams day count. Settle by reading kit/BLUEPRINT.md:399 and kit/LICENCES.md:161 (not read).
- Neighbour (outside slice): ship/tree/run/product (key guard, SS 2.1, D5), per DEVELOPMENT-PLAN.md:27-36.
