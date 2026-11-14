## RESULT AMEND-7
status: done
summary: Amendment 7 is committed as 973f67c on task/AMEND-7-amend-7. M08 gains five tasks, M08-T08 to M08-T12, covering D1 to D7 and the permission docs and config. M08-T07 now keeps Exchange in the guided delegated path within one sign-in; if Microsoft makes that impossible, it stops and records the limit for G. M08-T06 now scores 64 rows instead of 35. The ownership order now covers every shared file. This adds three dependencies: M08-T04 waits for M08-T10, M08-T05 waits for M08-T07, and B's repository change waits for M08-T07. The D29 reversal is written into M08-T10. Weights are unchanged. Notes are in .plan/work/AMEND-7/notes.md.
changes: .plan/milestones/M08-collection-completeness.md, .plan/master-plan.md, .plan/BACKLOG.md
verification: percent.py --check pass (before and after, on the final commit); every DoD command passes bash -n; the M08-T06 DoD command passes a synthetic good result and fails a bad one; the profile and preset opt-in check runs and exits 0; gitleaks pre-commit hook passed
risks: 1) ARCHITECTURE.md's tier A review binding list still names only M08-T01, T04 and T05; the orchestrator should add M08-T07, T09 and T12 (that file is outside this brief). 2) The critical path is now M08-T01, T07, T03, T04, T05, T11, T12, then T06, and the trial's end still bounds it. 3) D6's delegated scope and the admin route are not yet confirmed from a primary source; the task stops with a named skip if a second prompt or a write route would be needed.
questions_for_g: none
### Findings
- M08-T07 (changed): codex, S to M, tier A. Keeps Exchange via the shared cache and `-AccessToken`, and writes `exchange-one-sign-in: met|limit`.
- M08-T08 (new): codex, M, tier B. D1 auth methods, D3 withheld classifications, D7 site-permission reads.
- M08-T09 (new): sol, M, tier A. D2 per-item batch 429 retry with pacing.
- M08-T10 (new): codex, M, tier B. D4 DKIM and D5 DMARC NXDomain (reverses D29); vectors updated, rule packs with no drift.
- M08-T11 (new): codex, M, tier B. Permission docs and config with a parity test; folds in the CHANGELOG lines of T08 to T10.
- M08-T12 (new): sol, L, tier A (hard). D6 SharePoint admin read: opt-in, certificate or one sign-in, guard-tested no-write.
- M08-T06 (changed): orchestrator, M, risk:high. Scope 64 rows, target 62. Adds AAD 3.3, 3.4, 3.5, 3.6, 5.2, 5.3, 5.5, 5.6, 5.7 and 7.4 to 7.9; EXO 3.1, 4.1 to 4.4 and 7.1; SPO 1.1, 1.2, 1.3, 2.1, 2.2, 3.1, 3.2 and 3.3. The six phase D rows must read met or not met. SS 2.1 and 2.3 stay out of the scored rows.
- DoD: 8 to 11 items. Tier A review loop now covers T01, T04, T05, T07, T09 and T12; new tier B loop for T08, T10 and T11.
- Weights: unchanged (M00 6, M01 11, M02 11, M03 15, M04 13, M05 8, M06 10, M07 12, M08 14; sum 100).
- Percentages: M08 0% before and after; overall 69% before and after.
