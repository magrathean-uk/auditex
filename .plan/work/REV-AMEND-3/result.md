## RESULT REV-AMEND-3
status: done
summary: verdict: changes-required
  reviewed: 57de5d201d17ea0299b5b0e4a5bd37f67ccda4cc
  Reviewed by a second Claude account, not the author, because the other vendor's seats were at their limit. The scope, budget route and shared filter rule are right. Three stated conditions have no check: the data version M03-T02 trains on, the per-seed checkpoint limit, and the integrity of the pilot attempts.
changes: none (review notes in .plan/work/REV-AMEND-3/evidence.md and progress.md)
verification: percent.py --check pass (rc 0, 52%); 8 predicates extracted, bash -n pass; 23 scratch predicate trials (budget loop, pilot, data v2, large, M03-T08) behave as stated in evidence.md; real M02-T03 untouched clause pass; scan of added lines for paths, names and dates clean
risks: The pilot preference after the filter is optimistic by design: only both-order wins survive, judged by the same judge. | DEC-037 is still pending, so the M03-T06 precondition and the budget DoD item fail until it reads `- status: approved` and `- approver: G`.
questions_for_g: none
### Findings
- P1 scope: pass. Only the three files changed, BACKLOG correctly unchanged, done tasks and ticked items kept, weights unchanged, percent check passes.
- P2 tasks: criteria, files lines and precondition order (T08, T06, T07, T02) are sound. The predicates fail on bad input and pass on good input. Gaps: B1, B2, m2, m3.
- P3 pilot: the pass rule is `evaluate_seed` win_pass, recomputed exactly, so a `pilot: pass` that disagrees cannot pass. The filter rule is shared through M03-T08, the pilot is validation only, and `pilot: fail` blocks T07. Training case ids equal the v1 train set. Gaps: B3, m4, m5.
- P4 budget: the author is right. `STAGE_TASKS` plus `check_task` reject any task not listed, so neither a new stage name nor `prose` or `judging` can be used. `round-gpu-hours` lines are not picked up by `usage` (startswith). The 160 cap holds (160.01 fails), the total is 20,000 and the basecmp, large and build checks still work. Hours can escape only through usage's known limits, which the reviewer checks against the scheduler. Gaps: m1, m6.
- P5 M03-T02: three or more seeds and the selection rule are enforced by the kind. Gaps: B1, B2, m3.
- P6: bar, judge, prompt v3 and the frozen interface are unchanged; no dates, estimates or names in the changed files. Pass.
- B1 blocking, M03-explainer-training.md:52,18,87: nothing ties M03-T02's run to data v2. The `data-version:` line is copied by the author, and a run trained on v1 passes. Fix: in line 87, make the kind return `data-version: <version> <sha256 of its SHA256SUMS>` and require `data/explainer-v2` for M03-T02 runs, so `--result` compares it; add that case to the line 89 tests.
- B2 blocking, :49: the kind requires every seed run to name the same steps, and nothing caps the count, so "at most two per seed, chosen per seed" can fail the verify or go unchecked. Fix: "the same one or two steps for every seed, named in the selection rule before the first run"; M03-T08 refuses more than two named checkpoints per run on v2.
- B3 blocking, :84,97-98: dataround does not check the attempt sequence. Unchecked: a second attempt exists only after a first-attempt miss, the last attempt decides, the reason file is present, and the pass rule, headroom script and list, and judge config are byte-identical across attempts (only the prompt changes). Fix: add all of these to line 84, with tests for a second attempt after a pass and a changed pass rule; save the pass rule as `pass-rule.md` in `pilot-1/SHA256SUMS`.
- m1 minor, :86: `usage.recompute` and `_inventory` look up `TASK_STAGES[task]`, so only `parse_export` and its helpers can be reused. Fix: say so, keep the reconciliation rules, and fail on a missing `runs/usage/<task>/`.
- m2 minor, :17,110: `data/splits.json` is never checked, and T07's verify lacks the M02-T03 untouched clause. Fix: add `test "$(shasum -a 256 "$AIRR_KIT/data/splits.json" | cut -d' ' -f1)" = "$(sed -n 's/^data-splits-sha256: data\/splits.json \([0-9a-f]\{64\}\)$/\1/p' .plan/work/M02-T03/result.md)"` and the M02-T03 untouched clause to both.
- m3 minor, :51-52,18: the per-state and held-out-mix figures are not grepped. Fix: name `validation-preference-by-state:` and grep it with `validation-preference-heldout-mix:`.
- m4 minor, :95: prompt v2 could carry row examples. Fix: no validation or held-out row content in prompt v2; dataround refuses validation case ids in it.
- m5 minor, :97: the filter wording leaves out "fails a check", which lines 85 and 106 include. Fix: align the wording.
- m6 minor, master-plan.md:95-96: DEC-002 wants a resize amendment line under DEC-002 before the row changes. Fix: the orchestrator adds amendment 2 (dataround 0 -> 160, reserve 16,384 -> 16,224, balance read) and sets DEC-037 approved before merge. The M03 row in master-plan.md:109 says 25 against a computed 20.
- m7 minor, :81: M03-T08 changes the verifier the pilot's verdict rests on, but has no review gate. Fix: add a same-vendor review before M03-T06's first job and the other-vendor look in REV-M03-kit (as DEC-032).
