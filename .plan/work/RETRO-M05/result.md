## RESULT RETRO-M05
status: done
summary: Appended "## M05" to `.plan/RETRO.md` (Spend, Failures and retries, Proposed brief fixes, Keep). 19 ledger rows: 19 runs, $20.2787 recorded cost (7 codex2 rows have no cost), 6726 seconds, 5 retry attempts, 0 non-zero exits. Failures: 3 tasks needed repairs, 3 reviews could not run verify (mechanical), 1 DoD item open.
changes: .plan/RETRO.md (45 lines added, 0 removed); .plan/work/RETRO-M05/evidence.md
verification: `git diff --numstat .plan/RETRO.md` shows 45 additions, 0 deletions (pass). Ledger aggregation by launcher and role (pass).
risks: Ledger gaps: 7 codex2 rows have an empty cost_usd, and the M05-T04 read-through row names launcher `main`. The M05-T04 cause is not recorded in result.md. The SessionStart note says clean-development lifecycle registration failed; I did not run `clean-development doctor` because this brief forbids it.
questions_for_g: none
### Findings
- terra-implement.md: for M05-T02, validate every baseline field and exit non-zero on malformed input, with one test per field.
- The sol writer brief for M05-T03 (name not in the ledger; likely sol-architect.md): design.md must list identity-join and spelling-variant cases with expected outcomes before code.
- codex-review.md: before verify, link `.venv` from the main checkout and set `TMPDIR` in the reviewer worktree.
