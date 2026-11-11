## RESULT RETRO-M03
status: done
summary: M03 retro appended to `.plan/RETRO.md`. 31 runs, cost $3.2724 (10 codex2 rows have blank cost_usd, so the total is partial), 6576 seconds, 6 non-zero exits across 4 tasks. Totals are from the ledger; no rows were malformed.
changes: `.plan/RETRO.md` (appended "## M03", additions only); `.plan/work/RETRO-M03/notes.md`
verification: `git diff --numstat .plan/RETRO.md` shows 100 additions, 0 deletions (pass); aggregation by awk over the selected ledger rows (pass)
risks: Ledger has no cause for 5 of the 6 non-zero exits, so those causes are unknown. Two M03 result files are missing (M03-T05, M03-T06). The SessionStart hook reported clean-development lifecycle registration failed; I did not run `clean-development doctor` because this brief forbids it, so G should run it.
questions_for_g: none
### Findings
- `terra-implement.md`: write the RESULT block before any long verify step, or run verify under `run-job` (M03-T02 timeout, exit 124, no RESULT block).
- M03-T01 brief (luna, read-only): if a milestone verify needs a build, say so in the brief or drop the step (partial run skipped the wheel check).
- `_footer.md`: on any non-zero exit, write the stderr cause into result.md (4 exit-2 rows and 1 exit-1 row have no recorded cause).
- `codex-review.md`: link `.venv` from the main checkout before verify, else report "verification not runnable" (REV-M03-T03 and REV-M03-T04 blocked on it; repeats the RETRO-M02 proposal).
