---
id: M03
name: explainer-training
weight: 15
status: planned
---
# M03 explainer-training
Track B, same rules as M01. Ends at a judged build with a recommendation; whether a model explainer enters a product release, and how, is a later G gate. The Hugging Face upload stays parked until a build passes its bar and G says yes. No M03 run starts before the budget look.

## Goal
G has looked at the budget against the allocation balance before any M03 run; the candidate bases are compared on the explainer job with a measured noise band and EU-first decides inside it; the large runs on the chosen base select only on validation; one judged build is scored once on the clean held-out set; and G picks the final build (or none) from a written recommendation that lists the product-integration options.

## Definition of Done
- [x] Review: G looked at the spend so far and the allocation balance before any M03 run, and confirmed or moved the remaining stage caps (DECISIONS.md entry "AIRR budget look", approver G; moved caps are written into the master-plan budget table with that DEC): `grep -A8 '^## DEC-[0-9]* AIRR budget look' .plan/DECISIONS.md | grep -q '^- approver: G'`
- [x] The base comparison ranks every candidate with a noise band from at least three seeds, and the pick follows the EU-first rule, recomputed from the saved validation scores: `grep -qx 'base-comparison: complete' .plan/work/M03-T01/result.md && grep -q '^base-pick: ' .plan/work/M03-T01/result.md && "$AIRR_KIT/bin/kit-check" score runs/base-comparison --result .plan/work/M03-T01/result.md`
- [ ] The large runs selected their checkpoint on validation only, with the held-out set untouched: `grep -qx 'heldout-reads: 0' .plan/work/M03-T02/result.md && grep -q '^selected-checkpoint: ' .plan/work/M03-T02/result.md && "$AIRR_KIT/bin/kit-check" score runs/large --result .plan/work/M03-T02/result.md`
- [ ] The judged build is quantised, hashed and scored once on the clean held-out set against the bar, recomputed from the saved outputs and judgements: `grep -qE '^build-bar: (pass|fail)$' .plan/work/M03-T03/result.md && grep -qE '^build-sha256: [0-9a-f]{64}$' .plan/work/M03-T03/result.md && "$AIRR_KIT/bin/kit-check" score builds --result .plan/work/M03-T03/result.md`
- [ ] The recommendation and the product-integration options are written: `grep -qx 'recommendation: written' .plan/work/M03-T04/result.md`
- [ ] Review: G's pick of the final build, or of none, is recorded (DECISIONS.md entry "Explainer build pick", approver G): `grep -A8 '^## DEC-[0-9]* Explainer build pick' .plan/DECISIONS.md | grep -q '^- approver: G'`
- [ ] GPU-hours per stage, every job included, stay within the caps G approved (ARCHITECTURE.md budget binding): ``for s in basecmp large build; do row=$(grep "^| $s | " .plan/master-plan.md) && c=$(printf '%s\n' "$row" | awk -F'|' '{gsub(/[ ,]/,"",$4); print $4}') && printf '%s\n' "$c" | grep -qE '^[0-9]+$' && d=$(printf '%s\n' "$row" | awk -F'|' '{gsub(/ /,"",$5); print $5}') && grep -A8 "^## $d " .plan/DECISIONS.md | grep -q '^- approver: G' && grep -A8 "^## $d " .plan/DECISIONS.md | grep -q '^- status: approved' && e=0 && for t in $(printf '%s\n' "$row" | awk -F'|' '{gsub(/,/," ",$3); print $3}'); do v=$(sed -n "s/^gpu-hours: $s \([0-9][0-9]*\(\.[0-9][0-9]*\)\{0,1\}\)\$/\1/p" ".plan/work/$t/result.md" | head -1) && test -n "$v" && e="$e+$v" || exit 1; done && test "$(printf 'r=0\nif (%s <= %s) r=1\nr\n' "$e" "$c" | bc)" = 1 || exit 1; done && "$AIRR_KIT/bin/kit-check" usage --results .plan/work``
- [ ] Review: a reviewer of the other vendor from the run tasks' author reruns `kit-check all` on the recorded artefacts and checks the checkpoint and build hashes and the scheduler accounting on the system (ARCHITECTURE.md kit verification interface): `grep -qE '^[[:space:]]*(summary: )?verdict: approve' .plan/work/REV-M03-kit/result.md`

## Tasks
| id | title | owner | size | tags | status |
|---|---|---|---|---|---|
| M03-T01 | Compare the candidate bases on the explainer job | terra | M | debug | done |
| M03-T02 | Run the large training runs on the chosen base | terra | M | debug | todo |
| M03-T03 | Build, hash and judge the final explainer build | terra | S | - | todo |
| M03-T04 | Write the recommendation and the product-integration options | sol | S | - | todo |
| M03-T05 | Add the explainer score kind to the kit verifier | sol | S | hard | done |

## Acceptance criteria
### M03-T01 Compare the candidate bases on the explainer job
- Preconditions: M01-T05, M02-T03, M02-T05 and M02-T06 done (held-out form or per-state scoring fixed, DEC-013); the bar's DEC entry and the "AIRR budget look" DEC entry exist.
- Candidates: Ministral 3 8B, Ministral 3 14B, Gemma 4 31B and Qwen3.8-27B, plus Qwen 4 if open weights under an open licence are on the Qwen organisation's hub when the task starts (checked and stated). Snapshots are fetched straight onto Isambard-AI at pinned revisions.
- Same data, same recipe family and the same judging method for every base; at least three seeds each; selection on validation only. Ranks by the bar's measures with the noise band; EU-first decides between bases inside the band. Validation predictions and judgements are saved with `SHA256SUMS`.
- Writes `base-comparison: complete`, `base-pick: <base and revision>` and `gpu-hours: basecmp <used>` under `### Findings`.
- verify: `grep -qE '^heldout-form: (collected|per-state)$' .plan/work/M02-T06/result.md && grep -qx 'base-comparison: complete' .plan/work/M03-T01/result.md && "$AIRR_KIT/bin/kit-check" score runs/base-comparison --result .plan/work/M03-T01/result.md`
- files: `runs/base-comparison/**` and `runs/usage/M03-T01/**` in the AIRR kit folder; `.plan/work/M03-T01/result.md`

### M03-T02 Run the large training runs on the chosen base
- Preconditions: M03-T01 done; the "AIRR budget look" DEC entry exists.
- Sweeps the settings M03-T01 showed matter (learning rate, LoRA rank or full fine-tune, epochs) on the full prose data within the `large` cap of the budget table; the checkpoint selection rule is written before the first run and selects on validation by the bar's measures.
- The held-out set is not read (`heldout-reads: 0`, checked from the job logs, which are saved with `SHA256SUMS`).
- Writes `selected-checkpoint: <run and step>`, `heldout-reads: 0` and `gpu-hours: large <used>` under `### Findings`.
- verify: `grep -qx 'heldout-reads: 0' .plan/work/M03-T02/result.md && "$AIRR_KIT/bin/kit-check" score runs/large --result .plan/work/M03-T02/result.md`
- files: `runs/large/**`, `runs/large-ceiling-probe/**` (DEC-034) and `runs/usage/M03-T02/**` in the AIRR kit folder; `.plan/work/M03-T02/result.md`

### M03-T03 Build, hash and judge the final explainer build
- Preconditions: M03-T02 and M02-T06 done; scored on the set and with the reporting M02-T06 fixed (`heldout-form: collected` uses its resealed set, `per-state` reports every bar figure per verdict state).
- Quantises the selected checkpoint (Q5_K_M and one higher-precision variant) with a parity check against the unquantised adapter, records sha256 for each file, and scores the build once on the clean held-out set with the deterministic checks and the judge, against the bar and against the template explainer; outputs and judgements are saved with `SHA256SUMS`.
- Drafts a build card that names the base, data, method and scores and names no infrastructure; the build stays on project storage, and any copy off the system follows the storage routing (no telling first, G's download ruling).
- Writes `build-bar: pass` or `build-bar: fail`, `build-sha256: <64 hex>` and `gpu-hours: build <used>` under `### Findings`.
- verify: `grep -qE '^heldout-form: (collected|per-state)$' .plan/work/M02-T06/result.md && grep -qE '^build-bar: (pass|fail)$' .plan/work/M03-T03/result.md && "$AIRR_KIT/bin/kit-check" score builds --result .plan/work/M03-T03/result.md`
- files: `builds/**` and `runs/usage/M03-T03/**` in the AIRR kit folder; `.plan/work/M03-T03/result.md`

### M03-T04 Write the recommendation and the product-integration options
- Precondition: M03-T03 done and `REV-M03-kit` approves.
- Recommends ship-later, keep researching or stop, from the scores, the bar and the spend; lists the product-integration options with their cost to the product's boundaries (template stays the default and the fallback in every option; no verdict from the model; local only, nothing leaves the machine), each with what it would change in the repository, and the Hugging Face upload as a separate yes or no.
- Writes `recommendation: written` under `### Findings`; the orchestrator brings it to G for the build pick.
- verify: `grep -qx 'recommendation: written' .plan/work/M03-T04/result.md`
- files: `.plan/work/M03-T04/result.md`

### M03-T05 Add the explainer score kind to the kit verifier
- Added by DEC-032. Precondition: M02-T05 done. Runs while the M03-T01 jobs are queued and is done before the M03-T01 collecting round, which writes its `measures.json` to this kind's schema.
- A new check module `checks/explainer_score.py` exports `SCORE_KINDS` with one kind for explainer runs scored on validation (the base comparison and the large runs), plugged in the way `bin/README.md` describes; the frozen interface (`bin/**`, `checks/{selftest,score,usage}.py`) is not changed.
- Given the verified run folder, the kind recomputes from the saved validation outputs and judgements alone, per base, seed and checkpoint: the frozen checks' pass counts and the bar's measures (`checks/bar.py` `evaluate_seed` and the `checks/calibration.py` parsers imported unchanged, parameters from `judging/bar/bar.json`); the selected checkpoint per seed by the selection rule of runbook section 13; the rank with the noise band from the seeds; and the pick by the EU-first rule inside the band. It does not import or run anything under `runs/**`.
- It fails when a recomputed figure, selection or pick differs from `measures.json`, when a file it reads is missing from the run's `SHA256SUMS`, when a path under `heldout/` or `heldout-collected/` is named, or when a base has fewer than three seeds. It returns the lines the M03-T01 and M03-T02 criteria name (`base-pick:`, `selected-checkpoint:`) so that `--result` compares them as the verifier compares every other line.
- The `measures.json` schema of the kind is written in the module docstring. Tests under `checks/tests/` cover a passing synthetic run and each failure above (an altered judgement, an altered selection, a wrong pick, an unpinned file, a held-out path, two seeds); the kit's existing tests still pass. The kind is tried on a scratch copy of `runs/base-comparison/smoke1` with a `measures.json` written to the schema, and the result says what it printed.
- Writes `explainer-score-kind: <kind name>` and `kit-tests: pass` under `### Findings`.
- verify: `grep -q '^explainer-score-kind: ' .plan/work/M03-T05/result.md && grep -qx 'kit-tests: pass' .plan/work/M03-T05/result.md && "$AIRR_KIT/bin/kit-check" selftest --result .plan/work/M01-T03/result.md`
- files: `checks/explainer_score.py`, `checks/tests/test_check_explainer_score.py` and `checks/SHA256SUMS` (its own module's lines only) in the AIRR kit folder; `.plan/work/M03-T05/result.md`
