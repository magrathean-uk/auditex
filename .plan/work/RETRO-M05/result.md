## RESULT RETRO-M05
status: done
summary: 36 ledger rows selected; 36 runs, 34.8608 USD recorded, 12942 seconds, 0 non-zero exits. Codex2 rows (11) have no recorded cost, so the total understates spend.
summary: Three mechanical verify blocks and two review results missing from `.plan/work/`, plus plan v3 and v4 reusing the M05 ids. Four proposed brief fixes.
changes: .plan/RETRO.md
verification: `git diff --numstat .plan/RETRO.md` shows 66 additions, 0 deletions (pass); no other verify command is named in the brief
risks: Plan v3 (9-10 Nov) and v4 rows share task ids, so the spend split by era is by date only. Causes for some reruns are not recorded in any result file.
questions_for_g: none
### Findings
- Review briefs (codex-review.md, sol-review.md): record verify as "pending: orchestrator runs" when `.venv` or the read-only sandbox blocks it.
- Review briefs: forbid `clean-development doctor` for reviewers (REV-M05-T01 records a failed doctor run).
- Review briefs: write one `result-N.md` per review and never overwrite; REV-M05-T03-privacy and REV2-M05-T03 have ledger rows but no result.md.
- Dispatch record (no brief names it): set `plan_version` on every row; only 3 of 36 selected rows carry it.
