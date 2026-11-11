## RESULT RETRO-M04
status: done
summary: 16 M04 ledger rows (7 writer, 9 review), 0 non-zero exits, recorded cost $24.7797. The 9 review rows have blank cost_usd, so the true total is higher. Seconds total 7501. Four attempts or gaps: M04-T02 took 3 repair rounds (causes for rounds 1-2 not recorded), REV-M04-T02 was blocked by sandbox writes, M04-T03 ran twice with no recorded cause, and REV-M04-T01 verify was untestable (`.venv` missing).
changes: .plan/RETRO.md (appended "## M04" only, 145 additions, 0 deletions); .plan/work/RETRO-M04/evidence.md (the 16 ledger rows)
verification: `git diff --numstat .plan/RETRO.md` shows additions only: pass. No deletion lines in the diff: pass.
risks: Spend is a lower bound because review rows have no cost. The SessionStart hook asked for `clean-development doctor`; I did not run it because this brief forbids it. The doctor failure is also reported by REV-M04-T01, REV-M04-T02 and REV-M04-T03.
questions_for_g: none

### Findings
- codex-review.md: link `.venv` from the main checkout before verify; otherwise report "verification not runnable" with the path (REV-M04-T01; repeats RETRO-M03).
- codex-review.md: record sandbox-blocked temp writes as the cause and run verify with a `$TMPDIR` basetemp (REV-M04-T02).
- sol writer brief (not named in the ledger; likely sol-architect.md): list every binding form the scanner must cover in the acceptance criteria up front (M04-T02 repair-3 gap).
- _footer.md: on any re-run, write the reason into result.md, since the ledger has no cause column (M04-T03 second run, M04-T02 repair causes).
