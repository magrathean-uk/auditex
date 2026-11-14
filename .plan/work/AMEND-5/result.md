## RESULT AMEND-5
status: done
summary: Milestone M08 is written with six tasks in DEC-059's order: A1, A2, B, C, D, then E. It has seven Definition of Done items, each checked by a command or a "Review:". The master plan, ARCHITECTURE and BACKLOG are updated, the percent check passes, and the commit is b39cae2.
The proposed weights are not applied yet. M08 is committed at weight 0 because applying the weights means editing the frontmatter of M00-M02 and M04-M06, and the brief kept those files out of scope. The orchestrator applies them at the re-baseline.
A1 takes the certificate-auth code from the unmerged branch wt/collect-certauth-1, copying what fits and never merging it (that branch is 359 commits behind main).
changes: .plan/milestones/M08-collection-completeness.md (new), .plan/master-plan.md, .plan/ARCHITECTURE.md, .plan/BACKLOG.md
verification: percent.py --repo . --check pass (exit 0) on b39cae2; the proposed weights pass the same check on a scratch copy and give 70%; the DoD adapter command fails on main as expected (exit 5, five sections missing); every named test file exists, apart from three that the tasks create
risks: 1) Not verifiable offline: whether the Teams admin API accepts a certificate token, whether the app-only compliance session works with only Global Reader, and whether Power BI has an API for the admin setting. 2) M08-T06 depends on phase D, the A2 and B writes and the trial's end. 3) Until the weights are applied, the 84% figure leaves out M08's work.
questions_for_g: none (the manager approves the proposed weights at the re-baseline; recommended as proposed)
### Findings
- M08-T01 A1 certificate credentials, Teams in app mode: sol, M, hard risk:high (tier A: Codex review plus CHK)
- M08-T02 A2 reader-app certificate key credential (operator script): sol, S, risk:high (both providers)
- M08-T03 B Power BI and Power Platform enablement (scripts and docs): sol, M, risk:high (waits for EXP-m08-pbpp; stops for the manager if a kit verdict would change)
- M08-T04 C Teams app-settings read and adapter: codex, M, risk:high (tier A: Opus review plus CHK)
- M08-T05 D compliance session, DLP and alert-policy adapters: sol, L, hard risk:high (stops for the manager if it needs a role beyond Global Reader)
- M08-T06 E app-only re-collection and kit comparison: orchestrator (run by the tenant chat), M, risk:high
- weights old to new: M00 7 to 6, M01 13 to 11, M02 14 to 11, M03 15 to 15, M04 16 to 13, M05 10 to 8, M06 13 to 10, M07 12 to 12, M08 new 14 (committed at 0 until applied)
- reasoning: M08 is about the size of M04, so its 14 points come from the finished milestones in proportion; M03 and M07 keep their weights so their open items still count as work left
- overall: 84% before, 70% after applying (computed with percent.py on a scratch copy); the committed tree still reads 84%
- to apply: the frontmatter weights above, percent.py --write, a STATE re-baseline line "from 84% to 70% (DEC-059)"; notes in .plan/work/AMEND-5/notes.md
