## RESULT RETRO-M06
status: done
summary: 21 ledger rows selected (M06- and REV-M06- ids, plus EXP-m06-wheel and VAL-v4). Total 21 runs, $3.2354 recorded (8 codex and astra rows have no cost), 14780 s, 2 non-zero exits. Failure count 5: 2 non-zero ledger exits, 3 recorded only in result.md. M06-T04 has no ledger row; M06-T05 has two.
changes: .plan/RETRO.md (appended "## M06" only); .plan/work/RETRO-M06/{evidence.md,notes.md,progress.md}
verification: git diff --numstat .plan/RETRO.md pass (48 additions, 0 deletions); ledger parse by python3 pass (no malformed rows)
risks: M06-T02 attempt 1 (row 266) cause is lost because result.md was overwritten; brief file names under ~/.claude/skills/plan/briefs/ were not checked (inputs limited to ledger and results)
questions_for_g: none
### Findings
- Candidate or release brief: link the main `.venv` into the candidate worktree before step 1 (M06-T02 step 1 failed without it).
- Release brief: run `make dist` under `umask 077` and have the reproducible-build check build under two umasks (M06-T04 wheel hash differed by umask).
- `_footer.md`: on verify deferred (exit 75), record 75 in the ledger and name the deferred command and slot holder (M06-T01 row shows exit 1).
- `_footer.md`: keep each failed attempt's summary before a retry overwrites result.md (M06-T02 attempt 1 cause lost).
