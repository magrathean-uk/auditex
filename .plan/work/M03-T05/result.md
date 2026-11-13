## RESULT M03-T05
status: done
summary: Repair round after REV-M03-T05: kit checks/explainer_score.py now enforces rulings (a)-(h). Seeds are one shared set for every candidate (exactly 42, 43, 44 for M03-T01). Every validation row is scored. Checkpoints are exactly those in each run's checkpoint-hashes.txt, with the same steps for every run. The run folder's SHA256SUMS must be complete and every seed-run folder belongs to exactly one candidate.
  Relabelled seed runs are refused (a shared generations sha256 or adapter hash). The report must carry base-pick for M03-T01 and selected-checkpoint for M03-T02. DEC-033 union band on a top tie, failing only when no Mistral base is inside. training-run.json is scanned for held-out paths. The docstring cites DEC-033 and gives the schema.
  The round-1 tie test is replaced by three DEC-033 tests. 15 new tests, one or more per fix. All 15 new tests fail on the round-1 module.
  Reviewer trials, unmodified: 35 of 35 exit 1, 22 of them on rows first (expected). Adapted to the new preconditions: 5 pass and 30 fail, every one as expected.
  smoke1 trial now fails on seeds (one copy) and rows (three relabelled copies), as expected. Findings smoke-trial and section-13-gaps carry the repaired behaviour.
changes: kit checks/explainer_score.py (rewritten); kit checks/tests/test_check_explainer_score.py (30 tests); kit checks/SHA256SUMS (explainer_score.py line only). Also .plan/work/M03-T05/{notes.md (repair section), evidence.md, progress.md, scripts/}. No repository edits, no commits.
verification: python -B -m unittest discover -s checks/tests (from the kit folder): pass, 84 tests (54 existing, 30 explainer); run directly as the brief allows for the kit's own tests (both host slots were busy)
verification: judging/tests 17 OK; judging/bar/tests 13 OK; heldout-collected/tests 23 OK; bin/SHA256SUMS 11 of 11 OK; checks/SHA256SUMS differs from round 1 only in the explainer_score.py line
verification: the 30 tests against the round-1 module on a scratch kit: 17 fail (all 15 new, plus the 2 whose expected message moved to the completeness check)
verification: reviewer scripts .plan/work/REV-M03-T05/scripts/ unmodified on a scratch kit copy: 35 trials, 35 exit 1. 22 fail on rows (24 of 267), 13 on their own check first.
verification: adapted copies (scripts/harness-adapted.py, trials-adapted.py, cut_validation.py; 24-row validation file in the scratch kit): 35 trials, 5 pass (A, A with result line, G, G2, T1c) and 30 fail, all as expected; a rerun from the saved scripts gave identical outcomes
verification: verify command, both greps pointed at a scratch copy of the Findings lines under TMPDIR, then kit-check selftest --result .plan/work/M01-T03/result.md: pass (exit 0)
risks: runs/base-comparison/smoke1 counts as a seed-run folder under ruling (d). The M03-T01 collecting round must move it out of the scored folder before sealing, or the kind fails ("seed-run folder smoke1 belongs to no candidate"). The collecting round must also list every file, checkpoint-hashes.txt included.
risks: The reviewer's unmodified trials cannot reach most checks now (rows fail first). The adapted scripts in .plan/work/M03-T05/scripts/ are the meaningful rerun; G2 passes only with the DEC-033 band writer.
risks: Rule (e) compares whole generations files and adapter hashes. A copied run with reordered rows and a rewritten checkpoint-hashes.txt would pass, which is deliberate forgery beyond the trust root (as T1c). Which seed M03-T02 reports is still its own unwritten rule.
questions_for_g: none
### Findings
explainer-score-kind: explainer-validation-v1
kit-tests: pass
smoke-trial: one seed copy FAIL on the seed count; three seed-relabelled copies FAIL on rows (validation_rows 24, not the 267 rows); both expected after the repair
section-13-gaps: an exact tie at the top follows DEC-033 (union of the tied seed ranges, EU-first unchanged); the kind fails only with no Mistral base inside that band, and on Mistral bases tied on mean and size; notes in .plan/work/M03-T05/notes.md
reviewer-trials: unmodified 35 of 35 exit 1 (22 on rows first, expected); adapted 35: 5 pass, 30 fail, all as expected; .plan/work/M03-T05/evidence.md
repair: done
