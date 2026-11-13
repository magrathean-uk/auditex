## RESULT REV-M03-T05
status: done
summary: verdict: approve
  I rebuilt the 36 trials with my own scripts so each reaches the check it aims at, and added 14 extras. All 50 behave as expected, and an honest full-size M03-T01 run passes with the independently computed pick.
  Rulings (a) to (h) and DEC-033 are implemented as written. No blocking defect.
  Two advisory items: an honest run fails while smoke1 stays inside runs/base-comparison, and ruling (e) compares file bytes.
changes: none to the kit or the repository; wrote .plan/work/REV-M03-T05/{evidence.md, notes.md (round 2 sections prepended), progress.md, scripts/cutkit2.py, harness2.py, trials2.py, smoke2.py, fullrun2.py}
verification: scripts/trials2.py on a scratch kit with validation cut to 24 rows: 47 of 47 as expected
verification: scripts/smoke2.py on an uncut scratch kit: 3 of 3 fail (one copy on the seed count; three copies on rows, including validation_rows forged to 267)
verification: scripts/fullrun2.py (4 candidates x seeds 42-44 x 5 checkpoints x 267 rows): pass with pick m8; a wrong base-pick line fails; smoke1 left in the folder fails
verification: shasum -a 256 -c kit/bin/SHA256SUMS 11 of 11 OK and kit/checks/SHA256SUMS 6 of 6 OK; checks/tests on a byte-identical scratch copy: 84 tests OK
risks: There is no earlier copy of kit/checks/SHA256SUMS to diff against. The five other lines verify against modules dated before both rounds.
risks: Consistent forgery of every run's checkpoint-hashes.txt and files, like T1c for judgements, is beyond the trust root.
questions_for_g: none
### Findings
1. Trials: no outcome is wrong.
  - The 9 that wrongly passed now fail, each on its own check: B, C, C2, D, E, F, T6f, T7d and smoke1 (rows and seeds).
  - G and G2 now pass with pick m8.
  - The 22 that failed rightly still fail on their own checks. A, A with the result line, and T1c (inherent) pass.
2. Rulings, all as written, in kit/checks/explainer_score.py:
  - (a) :237, :474-482, :494-496
  - (b) :290-294, :342-346, :387-397
  - (c) :348-375, :497-502
  - (d) :593, :234-236, :241, :595-598
  - (e) :485-492
  - (f) :213-215, with the task bound to the result at :663
  - (g) :530-550, with the docstring at :31-39 and the tests at :476-509
  - (h) :333
  - DEC-033: union band at :533, EU-first unchanged, failure only on a tie with no Mistral base inside. Trial G4 (a Mistral base inside only the union band) passes; G4b (one tied base's band) fails; G3 and G5 fail.
  - Advisory: trial E3 passes. It is a copy of one seed run with its rows reordered and its checkpoint-hashes.txt rewritten. Smallest fix: compare the case-to-output map across seed runs, or require generations in case-id order.
3. New defects: none blocking. No new path lets a wrong pick pass. The frozen files and the other checks/SHA256SUMS lines are unchanged, and the kit's tests pass.
  - Advisory: an honest run fails while smoke1 stays in runs/base-comparison. The runbook's section 13 collecting step 3 seals the whole folder without saying to move smoke1. Smallest fix: the collecting round moves smoke1 out of runs/base-comparison before sealing.
