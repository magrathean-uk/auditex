## RESULT M03-T05
status: done
summary: Added kit checks/explainer_score.py: score kind explainer-validation-v1 (SCORE_KINDS plug-in, frozen interface unchanged), measures.json schema in its docstring.
  It reruns the frozen checks on saved validation outputs and ties each judgement to its output by the judge prompt's messages hash. It uses the calibration parsers and bar.evaluate_seed unchanged, and applies runbook section 13 in exact fractions: per-seed selection, rank, noise band and EU-first pick.
  Where section 13 is silent (an exact tie at the top of the rank; Mistral bases tied on mean and size) it fails instead of choosing.
  Trial on scratch copies of smoke1: an unchanged copy fails on the seed count as expected; three seed-relabelled copies print base-pick and pass; evaluate.py agrees; a flipped real judgement fails.
changes: kit checks/explainer_score.py (new); kit checks/tests/test_check_explainer_score.py (new, 16 tests); kit checks/SHA256SUMS (one line added for explainer_score.py, others unchanged); .plan/work/M03-T05/notes.md and progress.md. No repository edits, no commits.
verification: python -B -m unittest discover -s checks/tests (from the kit folder): pass, 70 tests (54 existing, 16 new)
verification: judging/tests pass; judging/bar/tests pass; heldout-collected/tests pass (23 tests)
verification: verify command, both greps pointed at a scratch copy of the Findings lines under TMPDIR, then kit-check selftest --result .plan/work/M01-T03/result.md: pass (exit 0)
verification: kit-check score on scratch smoke1 copies: one seed FAIL "candidate m8 has 1 seed run(s); runbook section 13 needs 3"; three relabelled seeds PASS printing base-pick: mistralai/Ministral-3-8B-Instruct-2512-BF16@f6fae9795746f63c9be8344932f01275f3c63734
risks: M03-T02's selected-checkpoint: the kind requires a seed run of the picked configuration and that seed's section 13 checkpoint, but which seed is reported is left to M03-T02's unwritten rule and not recomputed; tighten the kind when that rule exists.
risks: A resumed judge job that leaves duplicate judgement rows fails the kind; the collecting round must deduplicate before sealing. Full-size cost is about two minutes for 12 seeds x 5 checkpoints.
risks: Same-vendor review of the module is still to be dispatched (DEC-032).
questions_for_g: none
### Findings
explainer-score-kind: explainer-validation-v1
kit-tests: pass
smoke-trial: one seed copy FAIL on the seed count (expected); three seed-relabelled copies PASS, base-pick mistralai/Ministral-3-8B-Instruct-2512-BF16@f6fae9795746f63c9be8344932f01275f3c63734
section-13-gaps: an exact tie at the top of the rank and Mistral bases tied on mean and size fail instead of being chosen; notes in .plan/work/M03-T05/notes.md
