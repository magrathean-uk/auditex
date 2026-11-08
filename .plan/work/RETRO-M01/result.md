## RESULT RETRO-M01
status: done
summary: 62 M01 ledger rows, 22.7271 USD recorded, 9862 s, 7 non-zero exits (5 partial, 2 blocked). Codex launchers record no cost on any of their 32 rows, so codex spend is unmeasured and the total covers 30 rows only.
summary: Largest failure sources: 4 reviews approved with `.venv` verification not run (read-only sandbox), 2 reviews hit a failing `clean-development doctor` check, and 6 partial or blocked runs have no recorded cause.
summary: M01-T02 shows four round-3/round-4 review cycles; the round-4 approval it cites has no result.md on disk, so I could not verify it.
summary: Ledger total and per-role totals reconcile to 62 runs and 9862 s.
changes: .plan/RETRO.md (appended "## M01" only); .plan/work/RETRO-M01/agg.py, .plan/work/RETRO-M01/evidence.md
verification: `git diff --numstat .plan/RETRO.md` shows 114 additions, 0 deletions - pass; ledger row-width check (all 12 columns) - pass; no em dashes in RETRO.md - pass
risks: Codex cost is not in the ledger, so codex spend is unknown, not zero. The SessionStart hook asked for `clean-development doctor`; I did not run it, per the brief. Brief-to-role mapping for the fixes is inferred; the ledger has no brief column.
questions_for_g: none
### Findings
- `codex-review.md`, `sol-review.md`: record `clean-development doctor` as an observation, never a verdict input (REV-M01-T02 changes-required on it; REV-M01-T03 approved with it FAIL).
- `codex-implement.md`, `terra-implement.md`: on non-zero exit, write one cause line into the RESULT summary (M01-T03, T07, T09, T11, T12 have no cause; repeats the M00 finding).
- `codex-implement.md`, `terra-implement.md`, `codex-review.md`, `sol-review.md`: orchestrator links `.venv` before dispatch; a reviewer that cannot link writes "verify not run" in its verdict (M01-T01, M01-T06; REV-M01-T08, -T09, -T10, -T12).
- `codex-implement.md`, `terra-implement.md`: if a listed file is open in another task, rebase onto main and run verify on the final commit before reporting done (M01-T07 conflict; M01-T09 done row with a failing commit).
