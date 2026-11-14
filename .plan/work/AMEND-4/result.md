## RESULT AMEND-4
status: done
summary: The parked-case amendment is committed as 2bb1ceb on task/AMEND-4-amend-4. M03 now closes at a written finding with a reopening rule. M03-T02's training, M03-T03 and M03-T07 are dropped and M03-T04 is re-scoped. M03 has 7 Definition of Done items, with the same 2 ticked and nothing new ticked.
  The probe result is kept by a `git mv` to `.plan/work/M03-T02/probe-result.md`. On a scratch copy of the recorded results, `kit-check all` passes (20 checks) after the move. No kit-side change or task is needed.
  Only M03's file was in scope, so the weights of the other milestones are proposed here but not applied. The orchestrator applies them when the amendment merges.
changes: .plan/milestones/M03-explainer-training.md, .plan/master-plan.md, .plan/ARCHITECTURE.md, .plan/BACKLOG.md
verification: percent.py --repo . --check: pass (65%) on the final commit; kit-check all on a scratch results copy: fail before the move (score discovery, M03-T02 only), pass after it; kit-check usage --result on the moved probe file: pass; kit-check dataround for M03-T06: pass; new DoD 3 and 6 and the verify lines of the dropped tasks: pass on the copy; DoD 4 and 5 and the M03-T04 verify: pass on synthetic records and fail on an altered spend figure; master-plan stays at 150 lines; path and name scan of the diff: clean
risks: Three steps are left to the orchestrator when the amendment merges: the `git mv` of the probe result, the five frontmatter weights followed by `percent.py --write`, and the "Explainer build pick" entry with "none" and "parked" in its decision line. | The pilot Definition of Done item is rewritten to `pilot: fail`. The brief named only items that need a trained model, but the old item could no longer be met.
questions_for_g: none
### Findings
- M03-T02: dropped because data v2 never existed. The ceiling probe stays as evidence in `probe-result.md`, which `kit-check usage --result` still recomputes.
- M03-T03: dropped because there is no model to build. No held-out row was scored and the build cap is unused.
- M03-T07: dropped because `pilot: pass` was never reached.
- M03-T04: re-scoped to write the finding. It must write these lines:
  - `finding-scores: probe 0.4757 pilot-1 0.5112 pilot-2 0.5337 bar 0.729`
  - why the judge is right, with counts from EXP-m03-losses and M03-T06
  - `product-explainer: template; model-in-1.5.0: none`
  - `heldout-scores: none`
  - `finding-spend:`, cross-checked against the three result lines
  - `reopen-rule: a new example writer passes the M03-T06 pilot check unchanged before any training is planned`
- DoD 3, pilot: now "ran to its rule and failed". Checked by `pilot: fail`, two attempts, `kit-check dataround`, and no data v2 in the kit.
- DoD 4, data v2: removed. DoD 5, three seeds: removed. DoD 6, judged build: removed.
- DoD 7, recommendation: becomes the finding item, with figures checked against the result lines they come from.
- DoD 8, G's pick: becomes the "Explainer build pick" entry, approver G, with a decision line that says none and parked.
- DoD 9, GPU-hours: covers basecmp (M03-T01), large (the probe file) and dataround (M03-T06) against their table caps and approved entries. Checked by `kit-check usage` and `kit-check dataround`.
- DoD 10, REV-M03-kit: covers M03-T01, the probe and M03-T06, plus the M03-T05 and M03-T08 checks. It checks only M03-T01's checkpoint hashes.
- master-plan: updated the vision, success criteria, scope, non-goals (Hugging Face upload and integration), the budget note (build cap and all of the large cap except the probe's hours unused; both stay as caps), the sequencing and risks 3 and 4.
- BACKLOG: added a "Later" line with the reopening rule, the next re-pick of base models and the allocation end of 31 Jan 2027 (DEC-002). Removed the integration, Hugging Face, build score kind and held-out reader lines; the reader lines are now pointed to on reopening.
- ARCHITECTURE: changed lines 41, 43 and 58, which named M03-T07 or M03-T03.
- Weights, old to new:

  | Milestone | Old | New |
  |---|---|---|
  | M00 | 7 | 7 |
  | M01 | 13 | 13 |
  | M02 | 14 | 14 |
  | M03 | 15 | 7 |
  | M04 | 16 | 17 |
  | M05 | 10 | 11 |
  | M06 | 13 | 17 |
  | M07 | 12 | 14 |

- Reason for the weights: M03's remaining work is now a write-up, a record and a review, so its weight goes mostly to the release (10 open items) and to the live kit phase and rollback.
- Overall percentage from `percent.py`: 64% before; 65% after this commit with the old weights; 65% with the proposed weights (computed on a scratch copy).
- Kit-side task: none needed.
- Details: .plan/work/AMEND-4/notes.md
