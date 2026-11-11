## RESULT REV-M02-T02
status: done
summary:
verdict: changes-required
reviewed: 2f29eb589eca
736 rows; 102 policies; 265/314 cells; 0 twins under both published and null-insensitive keys.
heldout.jsonl sha256 13ebcdffdeb1800fc55af45d05b968a323630def861d898d79c4da34869a168e
changes: none
verification: Pinned commit, OPA version and hashes pass; wrong pins refused; in-memory rebuild reproduced 4/4 files byte-for-byte; sealing 9/9; materialised training splits 4/4 match; trainer rejects 736/736 raw held-out rows. Unhashed tampering and changed annotated splits rejected. Planted twin: bare check accepts count 1; frozen result rejects it.
risks: Native tests stopped with 7 temporary-directory setup errors; replay and checker probes used memory. Storage doctor failed on lifecycle ownership; left unchanged.
questions_for_g: none
### Findings

1. **blocking** - kit/20261111-airr-v4/heldout/build_heldout.py:486: Evidence-only evaluation fails to reproduce 62/596 unmasked labels. Restoring omitted context still leaves 36 failures: 5 verdict flips, 27 undefined verdicts and 4 engine errors. Preserve absent fields, include every required dependency and evaluate the final rendered evidence before sealing.

2. **blocking** - kit/20261111-airr-v4/heldout/build_heldout.py:635: 140 labels are assigned `not_assessed` after evaluation, without evaluating the masked input. None reproduces that verdict under pinned Rego. Generate genuine Rego-labelled missing-input cases and rebuild.

3. **blocking** - kit/20261111-airr-v4/heldout/build_heldout.py:650: Zero formal twins conceals 138 same-policy, same-missing-section gate matches with training; filtering unrelated Power BI settings exposes 10 predicate-level matches. Make keys gate-aware and predicate-specific, then regenerate from disjoint seeds. Nearest-neighbour verdict-copy counts are 505/736 by decisive evidence and 476/736 by full-evidence tokens, versus 264/736 policy-majority; 707/736 policy/verdict combinations already occur in training or validation.

4. **blocking** - kit/20261111-airr-v4/heldout/build_heldout.py:725: Conflict deletion removes 19,235 rows across 64 policies: 1,147 met, 8,645 not_met, 9,425 not_assessed and 18 not_applicable. It entirely removes MS.EXO.13.1v1/not_met and MS.SECURITYSUITE.5.1v1/met. All 49 missing cells match the author’s list, but those two gaps are caused by conflict deletion. Repair the key and regenerate rather than censor conflicting labels.

5. **limit** - kit/20261111-airr-v4/checks/twins.py:175: A rehashed manifest with incorrect verdict counts, missing cells, commit and comparison count still passes unchanged result measures. Validate these fields against recomputed facts and pinned inputs.

6. **limit** - kit/20261111-airr-v4/checks/twins.py:97: Comparison covers the annotated v10 pool rather than verifying consumed training files; prose without SHA256SUMS or recognised filenames is skipped. Require an explicit manifest of every consumed training and validation split, verify its hashes and reject incomplete discovery.
