## RESULT RETRO-M00
status: done
summary: M00 retro appended to `.plan/RETRO.md`. 65 ledger rows counted (60 M00/REV-M00 rows plus 5 PLAN-v4 rows, which name M00-T06): 21 non-zero exits across six tasks.
summary: Recorded cost is 39.8686 USD. It excludes the 16 codex-launcher rows, which have no cost_usd, and two timeout rows with blank cost.
summary: Most failure causes are not recorded in the ledger or result.md, so they are listed as not recorded.
changes: .plan/RETRO.md (appended section "## M00" only; numstat 57 additions, 0 deletions); .plan/work/RETRO-M00/progress.md
verification: `git diff --numstat .plan/RETRO.md` shows additions only (pass); ledger aggregation by launcher and role sums to 65 runs, 21 non-zero exits, 35789 seconds (pass)
risks: Spend is understated by the untracked codex cost; the proposed luna routing change is a plan-skill change, not a brief edit.
risks: Including PLAN-v4 (5 rows, 16.04 USD) is my reading of the selection rule; drop it if the milestone should count only its own tasks.
questions_for_g: none
### Findings
- `codex-implement.md` and `terra-implement.md`: a re-scoped attempt takes a new branch name and the milestone title; never reuse a task id for another scope (M00-T02, M00-T03, M00-T06).
- `codex-implement.md` and `terra-implement.md`: with a linked `.venv`, export `PYTHONPATH=<worktree>/src` before any test or smoke run (REV-M00-T06).
- Plan skill routing, not a brief: keep luna off implementation tasks (M00-T01: nine luna exits before a sol run passed).
