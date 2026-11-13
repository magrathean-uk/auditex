## RESULT REV-M03-T05
status: done
summary: verdict: changes-required
  The section 13 arithmetic is correct (selection, figures, rank, band, EU-first) and the bar is used unchanged. 70 kit tests OK; 36 scratch trials, see .plan/work/REV-M03-T05/evidence.md.
  Blocking: measures.json can drop candidates, seeds or checkpoints, or the base-pick line, and still pass. Relabelled identical seeds pass. A pick made on a subset of validation rows passes.
  Some exact ties at the top fail even when section 13 gives one pick.
changes: none to the kit or the repository; wrote .plan/work/REV-M03-T05/{progress.md,evidence.md,notes.md,scripts/harness.py,scripts/trials.py}
verification: python -B -m unittest discover -s checks/tests (from the kit folder): pass, 70 tests
verification: shasum -a 256 -c on kit/bin/SHA256SUMS and kit/checks/SHA256SUMS: pass
verification: scripts/trials.py on a scratch kit copy, 36 trials: 22 tamper cases fail as they should; 9 trials that should fail pass; 2 that should pass fail; detail in evidence.md
risks: No earlier copy of checks/SHA256SUMS was found to diff against (a broad search timed out; a targeted search found none). The five other lines verify against module files modified before this task.
risks: An altered judgement with measures.json rewritten to match passes. This is inherent: the raw judgement is the trust root.
questions_for_g: none
### Findings
1. Rule fidelity: kit/checks/explainer_score.py:393, 341-348, 416-453 match the text, and trial A (four bases, EU-first pick below a non-EU top) passes against an independent reading. Differences:
  - :204/:412 accept any 3 or more distinct seeds, not seeds 42, 43 and 44. Blocking; fix: require exactly {42,43,44}.
  - :388-392 accept any common subset of validation rows. smoke1 (24 rows) passes, but the text scores all 267. Blocking; fix: require the scored cases to equal every validation row.
  - :370-386 score only the checkpoints SHA256SUMS lists, so dropping one passes (trial D). Blocking; fix: require the checkpoints named in the run's checkpoint-hashes.txt.
  - :435-438 fail on any exact tie at the top, even where both readings give one pick (trials G and G2). Blocking but narrow; fix: work out the pick under each tied base's band and fail only if they differ.
  - :446-450 fail on Mistral bases tied on mean and size (the text is silent), and "smaller" is read as total_parameters. Advisory, acceptable.
2. Independence: every figure and the pick are recomputed. Nothing is taken from evaluate.py or anything else under runs/ (imports :83-89 only). But the candidate set, each candidate's run list and the report list come from measures.json unchecked:
  - omitting two candidates whose runs are still listed flips the pick and passes (trial B);
  - swapping seed 44 for a stronger seed 45, or listing four seeds, passes (trials C, C2).
  Blocking; fix: every run folder in SHA256SUMS must belong to exactly one candidate.
3. Tamper cases:
  - Fail as they should: altered judgement (unsealed, or resealed with stale measures); outputs swapped between checkpoints or seeds; judgement tied to another output; duplicated or dropped judgement row; any read file missing from SHA256SUMS; held-out or heldout-collected path in measures, SHA256SUMS or training-config; two seeds; tampered figures, rank, band or parameters.
  - Pass: three relabelled identical seeds (1 distinct generations file); an omitted run whose files stay listed. Blocking; fix: refuse seed runs of one candidate that share a generations sha256 or adapter hash.
  - Pass: a held-out path in training-run.json. Advisory; fix: scan it too.
4. Bar use: evaluate_seed, outcome and the calibration parsers come from the verified modules unchanged, with win_threshold and flag_cap from bar.json (:231). The bootstrap defaults equal bar.json. Unparsed and inconsistent pairs count half, as the bar counts them (:336-340; checked in trial A with mixed outcomes). No defect.
5. Interface: bin/SHA256SUMS verifies; checks/SHA256SUMS adds only this module's line; 70 tests OK. --result compares base-pick through the same core line check as every other line. But report (:180-184) lets an M03-T01 measures.json leave out base-pick, so a wrong base-pick line passes (trial F). Blocking; fix: require base-pick for M03-T01 and selected-checkpoint for M03-T02.
6. Tests: the 16 tests cover every failure the criteria list, for the stated reasons. test_tie_at_the_top_fails_instead_of_choosing asserts failure on a tie where either band gives m8, so it locks in the tie defect. Advisory; tests are missing for omission, relabelled seeds, dropped checkpoints, report without base-pick, a row subset and an inconsistent outcome.
