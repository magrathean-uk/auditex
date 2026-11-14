## RESULT RETRO-M04
status: done
summary: M04 retro appended to `.plan/RETRO.md`. Strict set is 65 runs (plus 16 rows of other ids that name M04 tasks, 81 in total). Recorded cost is 140.4442 USD (codex2 has no cost recorded on any row), 41548 seconds, 8 non-zero exits.
summary: Failures are 8 non-zero attempts across M04-T02, REV-M04-T02, M04-T03, M04-T04 and M04-T06. Two were mechanical (heavy slot busy), six have no recorded cause.
summary: Final status is done for M04-T02, M04-T03 and M04-T04. M04-T06 is partial and marked dropped in the milestone; REV-M04-T02 is done in the ledger but partial in its result.md.
summary: Not selected: PLAN-v3, PLAN-v4, RETRO-M04, GATE-M02-M04 and CHK-M04-T06 (no result.md).
changes: .plan/RETRO.md (120 additions, 0 deletions), .plan/work/RETRO-M04/notes.md, .plan/work/RETRO-M04/progress.md
verification: ledger aggregation with python3 over the selected rows: pass; `git diff --numstat -- .plan/RETRO.md` shows additions only: pass
risks: codex2 cost is missing from every total, so spend is understated.
risks: CHK-M04-T06 has a ledger row but no result.md, so it is excluded.
risks: M04-T06 is marked dropped while its last ledger row is partial.
questions_for_g: none
### Findings
- `~/.claude/skills/plan/briefs/_footer.md`: on a deferred verify (exit 75), record the exact command and slot holder in the summary. Backed by REV-M04-T02 and M04-T06.
- `~/.claude/skills/plan/briefs/terra-check.md`: run checks over about 10 minutes through `run-job`, not in the foreground. Backed by CHK-M04-T03.
- Not a brief change: save each failed attempt's summary before a retry overwrites result.md. Backed by six unexplained non-zero attempts in M04-T02, M04-T03 and M04-T04.
