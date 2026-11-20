## RESULT M11-T06
status: done
summary: Second round finished with `model-bar: fail (no base met the bar)` and `m11-gpu-hours: 345.97` (208.38 from T01-T04 plus 137.59 here).
summary: `qwen-a-1053` failed the sealed held-out (sentence pass 0.999385, 124 fallbacks, 8 contradiction rows, 4 completeness, 6 leaks, 0 header). M10 `qwen` on the same rows also failed (6 leak rows).
summary: The 6 leak rows are identical for both models, so it is a judge false positive, not a student leak.
summary: Mistral final step 2786 failed es150 (440 fallbacks, 12 contradictions, 8 completeness, 4 header), so it was dropped without a held-out run. Gemma was dropped on validation.
changes: none in the repository. `.plan/work/M11-T06/result.md` written, `progress.md` updated, `watch.txt` emptied. Scores are on the project store under `runs/m11t06/val/`.
verification: the `.plan/work/M11-T06/result.md` verify command passed (`model-bar` and `m11-gpu-hours` lines present). Lint did not run because no repo files changed. No job is queued.
risks: 1) The remaining failures (contradictions, runaway fallbacks, completeness) are model-side, so more data or steps is unlikely to help. 2) The judge false positive on product lines would fail any future bar, even for an off-the-shelf model, and is not fixed here. 3) GPU hours are summed from `sacct` job names, so any T06 job under another name would be missing.
questions_for_g: Recommendation: stop training and do not run another round. Decide whether to fix the leak judge as a separate task.
