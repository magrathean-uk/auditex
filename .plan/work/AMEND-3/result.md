## RESULT AMEND-3
status: done
summary: I applied all three blocking and seven minor review fixes to plan v4 amendment 3. Commit 97c80b6 is on task/AMEND-3-amend-3. M03-T02 is now tied to data v2 by a check, each seed is held to at most two judged checkpoints, and the order and integrity of the pilot attempts are checked. Scope, the budget route, the 160 cap, the filter rule, weights, done tasks and ticked items are unchanged.
changes: .plan/milestones/M03-explainer-training.md, .plan/ARCHITECTURE.md, .plan/master-plan.md
verification: percent.py --check pass (rc 0, master-plan.md 150 lines); bash -n on the 7 touched DoD items and verify commands pass; 20 trials on scratch result files under $TMPDIR with a stub kit-check all pass on good input and fail on bad input (good input rc 0; split file or v1 manifest changed, split line missing, v1 data version, version mismatch, missing by-state line, non-numeric held-out-mix value, missing or rejecting REV-M03-T08 all fail); added-line scan for paths, names and dates clean
risks: The B1, B2, B3, m1 and m4 checks live in the kit (M03-T08) and are only tested by that task's own tests; the plan predicates cover just the result lines. | The M03-T06 verify now needs .plan/work/REV-M03-T08/result.md, a new review gate the orchestrator must schedule. | DEC-037 stays pending (orchestrator), so the budget DoD item and M03-T06's precondition fail until it is approved.
questions_for_g: none
### Findings
- B1: the M03-T08 explainer-kind line now returns `data-version: data/explainer-v2 <sha256>` for runs on data v2 and requires every run under `runs/large/` to name it; T02 writes says the kind returns it; T02 verify and the large DoD item require the `data/explainer-v2 <64 hex>` form; T08 tests cover a v1 or unnamed run and a mismatched line.
- B2: the T02 selection rule now names the same one or two steps for every seed, fixed before the first run; the T08 explainer-kind line refuses more than two on a data v2 run; test added; the large DoD wording says at most two per seed.
- B3: the T08 pilot line adds the attempt-sequence checks: `pass-rule.md` in `pilot-1/SHA256SUMS`, a second attempt only after a miss with `revision-reason.md`, pass rule, headroom script and list and judge config byte-identical, and the last attempt decides. T06's pass-rule, revision and files lines match. Tests cover a second attempt after a pass, a missing reason file and a changed pass rule, headroom or judge config.
- m1: T08 round-hours line reuses only `parse_export` and helpers (states why), fails on a missing `runs/usage/<task>/`; test added.
- m2: the data v2 DoD item and T07 verify check `data/splits.json` against M02-T03's sha; T07 verify gains the M02-T03 untouched clause.
- m3: T02 writes `validation-preference-by-state:`; T02 verify and large DoD grep it and a numeric `validation-preference-heldout-mix:`.
- m4: T06 prompt line bars validation and held-out row content; T08 pilot line refuses validation case ids in prompt v2; test added.
- m5: T06 pass-rule filter wording now reads "fails a check or does not win in both orders".
- m6: master-plan.md M03 row corrected 25 to 20 (computed figure). The DEC-002 amendment 2 and the DEC-037 approval are left to the orchestrator.
- m7: T08 gets a same-vendor review `REV-M03-T08` before M03-T06's first job and the other-vendor look inside REV-M03-kit. It appears in the T06 precondition and verify, the REV-M03-kit DoD text and the ARCHITECTURE dataround line.
