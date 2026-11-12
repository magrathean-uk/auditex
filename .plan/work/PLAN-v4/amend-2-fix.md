# Plan v4 amendment 2 - one repair round

The check of your branch `task/PLAN-v4-plan-v4-amend-2` at 77b7f17 returned changes-required: `.plan/work/REV-PLAN-v4/result-5.md` in the main checkout, with its probes in `.plan/work/REV-PLAN-v4/evidence.md`. Continue on the branch.

1. Close D1, D2, D3, D4 and D5 as the review's fixes say, or with an equivalent predicate that fails on the same bad inputs (a copied result, a self-reported line, a wrong hash, a suite log older than the freeze, a missing M02-T06 result). Correct the "no code change" claim D1 names, and widen M02-T06's files line if the fix needs a kit file.
2. The nit under item 5: master-plan.md risk 8 says "before the trial ends (DEC-008)" with no date.
3. Change nothing else: weights, statuses, ticks and every other line stay. `percent.py --check` passes. Do not edit `.plan/STATE.md` or `.plan/DECISIONS.md`.
4. In the summary, list each of D1 to D5 with the path:line that closes it and the bad input you probed it with.
