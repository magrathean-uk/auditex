## RESULT PLAN-v4
status: done
summary: Amendment 1 applied: M04-T03, T04 and T05 now follow the approved design (revision 3) under DEC-004. That means the key is made at collection; older runs are masked with a temporary key until `auditex report prepare-key`; the smoke seeds keys (`seed`); the assessment schema enum changes in place with no dated copy. It also adds the test-update rule and the six amendments as tested criteria.
summary: New M00-T06 (DEC-005): an `--as-of` date on both offline runs, used by all eight smoke runs, plus a new M00 DoD item. M02-T02, T04 and T05 now own `checks/SHA256SUMS`. ARCHITECTURE and the master-plan success-criteria and sequencing lines are updated to match.
summary: Percentage before 13% (M00 58%), after 12% (M00 54%): current: 12%. I did not run `percent.py --write` because it rewrites STATE.md, so the master-plan table still shows M00 58 until your checkpoint.
summary: Done tasks and ticked items are unchanged. STATE.md and DECISIONS.md are untouched, as the amendment requires. The reset commit from the first round stands. Notes are in .plan/work/PLAN-v4/notes.md; the previous round's notes are copied to notes-2.md beside it.
changes: .plan/milestones/M00-foundation.md, .plan/milestones/M04-d5-keyed-pseudonyms.md, .plan/milestones/M02-explainer-data-and-judging.md, .plan/ARCHITECTURE.md, .plan/master-plan.md (135 lines); work-dir notes.md and notes-2.md
verification: percent.py --repo . --check pass (exit 0); bash -n on the 31 M00 and M04 DoD and verify commands pass; the new Makefile check behaves correctly in bash, zsh and sh (all eight runs dated passes, seven fails, today's tree fails); the DEC-004 seed line reads; git diff --check pass; no workstation paths in the plan files
risks: The M04-T03 temporary-key notice (DEC-004 amendment 6) may need `mcp_server.py`, which the design lists as unchanged; the files line allows it only if `redact_payload` cannot carry the notice.
risks: M00-T06 pins the smoke to the day the current digest fixture was recorded, not the demo's date, because the demo's date could change findings the digests hold. The fixture refresh may therefore change nothing.
risks: `checks/SHA256SUMS` is shared by M02-T02, T04 and T05, so they can never hold it at the same time; I wrote this into their files lines but not into the master-plan sequencing line, which the amendment limits to items 1 and 3.
questions_for_g: none
### Findings
| id | name | weight | DoD items | ticked |
|---|---|---|---|---|
| M00 | foundation | 8 | 13 | 7 |
| M01 | airr-bring-up | 15 | per file, unchanged | unchanged (38%) |
| M02 | explainer-data-and-judging | 15 | unchanged | 0 |
| M03 | explainer-training | 17 | unchanged | 0 |
| M04 | d5-keyed-pseudonyms | 18 | 8 | 1 |
| M05 | scanners-and-hygiene | 12 | unchanged | 0 |
| M06 | release-1-5-0 | 15 | unchanged | 0 |
current: 12% (before amendment: 13%); per-item notes in .plan/work/PLAN-v4/notes.md
