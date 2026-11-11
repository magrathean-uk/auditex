## RESULT RETRO-M01
status: done
summary: M01 retro appended. 73 ledger rows (69 M01-/REV-M01- plus VAL-v3 and REV-PLAN-v2, which name M01-T03 and M01-T04). Total cost $24.3623 across 37 costed rows; 36 codex/codex2 rows are blank, so this is a floor. 11987 s as recorded.
summary: 7 non-zero exits (5 partial, 2 blocked). Ids M01-T01 to T04 are reused by an earlier boundary-proof plan, so spend mixes two plans.
summary: Causes are not recorded for most failures; the earlier-plan tasks have no result.md, so I did not read raw logs.
changes: .plan/RETRO.md (59 additions, 0 deletions); .plan/work/RETRO-M01/evidence.md
verification: ledger aggregation script, pass (73 rows, 0 malformed); git diff --numstat .plan/RETRO.md, pass (additions only); em-dash grep on RETRO.md, pass (0)
risks: Blank Codex cost (36 rows) makes spend a floor. Id reuse means per-task figures are not reliable without the plan split. Clean-development lifecycle registration failed at session start; I did not run `clean-development doctor` because the brief forbids it, so G should check it.
questions_for_g: none
### Findings
- `codex-implement.md`: after an exit-2 launch within about 30 s, fall back to `terra-implement` on Claude rather than relaunching the same launcher. Backed by M01-T07 (codex2 exit 2 twice, then terra done).
- `terra-implement.md` or `luna-explore.md`: export the env var a verify reads, or name the records path the input is copied to. Backed by M01-T02 (verify fails with the variable unset) and M01-T02b.
- `sol-review.md` and `codex-review.md`: link `.venv` from the main checkout first; if blocked, report "verification not runnable" and name the covering run. Backed by REV-M01-T01 and REV-M01-T03.
