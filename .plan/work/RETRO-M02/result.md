## RESULT RETRO-M02
status: done
summary: M02 retro appended to .plan/RETRO.md, covering 61 ledger rows from the PLAN-v4 run onward. Total 61 runs, cost 162.0207 (46 rows have a cost; 15 are blank), 74821 s, 7 non-zero exits. All 7 were recovered by a later exit-0 row for the same task. Six of the seven have no recorded cause.
changes: .plan/RETRO.md (append only); .plan/work/RETRO-M02/evidence.md; .plan/work/RETRO-M02/progress.md
verification: git diff --numstat .plan/RETRO.md: pass (53 additions, 0 deletions); ledger row selection and awk totals: pass
risks: Earlier M02- rows from superseded plan versions are excluded because the ids were reused. The ledger header names 12 columns, but rows carry a 13th plan_version value.
questions_for_g: none
### Findings
- `~/.claude/skills/plan/briefs/_footer.md`: add a rule that runs expected to exceed about two hours are submitted with run-job, their job ids recorded in progress.md, and the worker exits so a short worker can collect. Backed by M02-T04's timeout (exit 124 at 10801 s).
- Not a brief change: the orchestrator should keep each partial or blocked summary before a retry overwrites it. Six of the seven non-zero exits have no recorded cause.
