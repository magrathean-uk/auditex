---
id: M02
name: explainer-data-and-judging
weight: 15
status: planned
---
# M02 explainer-data-and-judging
Track B, same rules as M01 (results only in `.plan/work/<id>/result.md`; code and data in the AIRR kit folder; `gpu-hours: <stage> <used>` per task; every measurement reproduced by `kit-check`). The explainer job is G's pick (gate answers): the model writes fuller explanations and remediation for a verdict the value rules already gave; it never decides or changes a verdict. Held-out and sealed rows never enter the public repository.

## Goal
Before any large run: the held-out twin count is reconciled under one written definition, a clean held-out set exists, the deterministic checks are frozen before any training data is generated, prose training data for the explainer job is built from training-split cases only and passes those frozen checks, and a judging method for free text (deterministic checks first, then a calibrated open-weight judge, no paid API) and its acceptance bar are validated and recorded.

## Definition of Done
- [ ] The twin definition is written and the 137 versus 318 counts are explained under it: `grep -q '^twin-definition: ' .plan/work/M02-T01/result.md && grep -qx 'twin-counts: reconciled' .plan/work/M02-T01/result.md`
- [ ] The clean held-out set has zero twins against every training split by that definition, no policy above its stated share cap, and is sealed in the kit with a recorded sha256, recomputed by the verifier: `grep -qx 'heldout-twins: 0' .plan/work/M02-T02/result.md && grep -qE '^heldout-sha256: [0-9a-f]{64}$' .plan/work/M02-T02/result.md && "$AIRR_KIT/bin/kit-check" twins --result .plan/work/M02-T02/result.md`
- [ ] The judging method is calibrated: deterministic checks catch every planted defect of their classes, and the judge meets its detection and position-swap consistency thresholds, recomputed from the saved judgements: `grep -qx 'judge-calibration: pass' .plan/work/M02-T04/result.md && "$AIRR_KIT/bin/kit-check" calibration --result .plan/work/M02-T04/result.md`
- [ ] The prose training data covers every policy and verdict state in the template, comes only from training-split cases, and every kept row passes the deterministic checks frozen by M02-T04 (same checks hash): `grep -qx 'prose-data: pass' .plan/work/M02-T03/result.md && h=$(sed -n 's/^checks-sha256: \([0-9a-f]\{64\}\)$/\1/p' .plan/work/M02-T04/result.md) && test -n "$h" && grep -qx "checks-sha256: $h" .plan/work/M02-T03/result.md && "$AIRR_KIT/bin/kit-check" checks --result .plan/work/M02-T03/result.md`
- [ ] The acceptance bar is validated against the template explainer and planted bad outputs and recorded as a DECISIONS.md entry before any M03 run: `grep -qx 'bar-validated: yes' .plan/work/M02-T05/result.md && grep -q '^## DEC-[0-9]* Explainer acceptance bar' .plan/DECISIONS.md && "$AIRR_KIT/bin/kit-check" bar --result .plan/work/M02-T05/result.md`
- [ ] GPU-hours per stage, every job included, stay within the caps G approved (ARCHITECTURE.md budget binding): ``for s in heldout prose judging; do row=$(grep "^| $s | " .plan/master-plan.md) && c=$(printf '%s\n' "$row" | awk -F'|' '{gsub(/[ ,]/,"",$4); print $4}') && printf '%s\n' "$c" | grep -qE '^[0-9]+$' && d=$(printf '%s\n' "$row" | awk -F'|' '{gsub(/ /,"",$5); print $5}') && grep -A8 "^## $d " .plan/DECISIONS.md | grep -q '^- approver: G' && grep -A8 "^## $d " .plan/DECISIONS.md | grep -q '^- status: approved' && e=0 && for t in $(printf '%s\n' "$row" | awk -F'|' '{gsub(/,/," ",$3); print $3}'); do v=$(sed -n "s/^gpu-hours: $s \([0-9][0-9]*\(\.[0-9][0-9]*\)\{0,1\}\)\$/\1/p" ".plan/work/$t/result.md" | head -1) && test -n "$v" && e="$e+$v" || exit 1; done && test "$(printf 'r=0\nif (%s <= %s) r=1\nr\n' "$e" "$c" | bc)" = 1 || exit 1; done && "$AIRR_KIT/bin/kit-check" usage --results .plan/work``
- [ ] Review: a reviewer of the other vendor from the run tasks' author reruns `kit-check all` on the recorded artefacts and checks the checkpoint and build hashes and the scheduler accounting on the system (ARCHITECTURE.md kit verification interface): `grep -qE '^[[:space:]]*(summary: )?verdict: approve' .plan/work/REV-M02-kit/result.md`

## Tasks
| id | title | owner | size | tags | status |
|---|---|---|---|---|---|
| M02-T01 | Reconcile the held-out twin counts under one written definition | terra | S | - | done |
| M02-T02 | Build and seal the clean held-out set | codex | M | - | todo |
| M02-T04 | Build, freeze and calibrate the judging method for free text | codex | M | hard | todo |
| M02-T03 | Build the prose training data for the explainer job | codex | M | - | todo |
| M02-T05 | Validate and record the explainer acceptance bar | sol | S | - | todo |

## Acceptance criteria
### M02-T01 Reconcile the held-out twin counts under one written definition
- Reads how the project counted 137 (the strict key in the v10 curation and `V11-DATA-PLAN.md`) and how INV4-kit-data counted 318 (longest-text match), and the 298 twin-free figure in PASS-model; explains each number under the definitions.
- Writes one twin definition that covers both verdict cases and explainer inputs (same policy and the same evidence that decides the verdict), with the reasons, as code in `heldout/twin_definition.py` that M02-T02's `twins` check imports; recounts test-v7 against the v10 train and validation splits under it.
- Writes `twin-definition: <one line>`, `twin-counts: reconciled` and `gpu-hours: heldout 0` on their own lines under `### Findings`. CPU only; counts only, no row content in `result.md`.
- verify: `grep -q '^twin-definition: ' .plan/work/M02-T01/result.md && grep -qx 'twin-counts: reconciled' .plan/work/M02-T01/result.md`
- files: `heldout/notes/**` and `heldout/twin_definition.py` in the AIRR kit folder; `.plan/work/M02-T01/result.md`

### M02-T02 Build and seal the clean held-out set
- Preconditions: M02-T01 done; M01-T03 done (it builds `bin/kit-check`, which this task's `twins` subcommand plugs into and its verify runs).
- Regenerates held-out cases offline from the pinned ScubaGear Rego (2446ad7, OPA 1.20.2, checked in this task) on synthetic tenants, removes every twin of any training or validation row by the M02-T01 definition, caps any one policy's share (stated; test-v7 had 39 per cent in one policy) and covers every policy that has a verdict state the explainer must explain.
- Freezes the set in the kit with a manifest and sha256; it is used once per build in M03-T03 and never for selection. Adds the `twins` subcommand.
- Writes `heldout-twins: 0`, `heldout-sha256: <64 hex>`, the row and policy counts and `gpu-hours: heldout 0` under `### Findings`. CPU only.
- verify: `grep -qx 'heldout-twins: 0' .plan/work/M02-T02/result.md && "$AIRR_KIT/bin/kit-check" twins --result .plan/work/M02-T02/result.md`
- files: `heldout/**` (except `heldout/notes/**` and `heldout/twin_definition.py`), `checks/twins.py` and `checks/SHA256SUMS` (its own check modules' lines only, DEC-003; M02-T02, M02-T04 and M02-T05 never hold it at the same time) in the AIRR kit folder; `.plan/work/M02-T02/result.md`

### M02-T04 Build, freeze and calibrate the judging method for free text
- Preconditions: M01-T04 done (the judge runs on the allocation in the qualified environment).
- Deterministic checks first, reusing the logic of the repository's `tests/explainer_checks/` (a copy in the kit, no repository import): stated verdict equals the rule verdict; every setting and value named appears in the evidence; policy id and evidence references are right; remediation does not contradict the baseline; output within the length limits the task sets for the fuller text. Their tree under `judging/checks/` is frozen before M02-T03 starts and its sha256 written as `checks-sha256: <64 hex>`; a later change to it reopens M02-T03.
- Then an open-weight judge of a different model family from the candidate base, run on the allocation, scoring faithfulness, completeness and actionability pairwise against the template explanation with position swap.
- Calibration set of planted defects (wrong verdict, invented value, missing remediation step, wrong policy, contradictory step, padding): the deterministic checks catch every planted defect of their own classes; the judge flags at least 90 per cent of the rest and agrees with itself under position swap on at least 90 per cent of pairs. Noise band by bootstrap over cases. Raw judgements are saved with `SHA256SUMS`; adds the `checks` and `calibration` subcommands.
- Saves the scheduler accounting export of its jobs under `runs/usage/M02-T04/`. Writes `judge-calibration: pass`, `checks-sha256: <64 hex>` and `gpu-hours: judging <used>` under `### Findings`.
- verify: `grep -qx 'judge-calibration: pass' .plan/work/M02-T04/result.md && "$AIRR_KIT/bin/kit-check" calibration --result .plan/work/M02-T04/result.md`
- files: `judging/**` (except `judging/bar/**`), `checks/{checks,calibration}.py`, `checks/SHA256SUMS` (its own check modules' lines only, DEC-003; M02-T02, M02-T04 and M02-T05 never hold it at the same time) and `runs/usage/M02-T04/**` in the AIRR kit folder; `.plan/work/M02-T04/result.md`

### M02-T03 Build the prose training data for the explainer job
- Preconditions: M02-T04 done (frozen deterministic checks; the qualified environment of M01-T04); M02-T02 done (so no held-out case leaks into training).
- Inputs per row follow the explainer job interface in ARCHITECTURE.md: policy, rule verdict and reason from the value rules, the evidence excerpt and the template explanation, produced with the released 1.4.0 wheel. Targets are fuller explanations and remediation written by an open-weight teacher run on the allocation (Mistral Small 4, Apache-2.0, accepted by G at the scope approval); no paid API.
- Every kept row passes the frozen M02-T04 deterministic checks at the recorded `checks-sha256` (same verdict, no value absent from the evidence, valid evidence references, remediation consistent with the baseline text); the drop count per check is recorded.
- Covers every policy and verdict-state cell of `configs/explainer-template.json`, with train and validation splits by case, never by row; the split manifests carry `SHA256SUMS`.
- Saves the scheduler accounting export of its jobs under `runs/usage/M02-T03/`. Writes `prose-data: pass`, `checks-sha256: <the M02-T04 value>`, the row counts and `gpu-hours: prose <used>` under `### Findings`.
- verify: `grep -qx 'prose-data: pass' .plan/work/M02-T03/result.md && "$AIRR_KIT/bin/kit-check" checks --result .plan/work/M02-T03/result.md`
- files: `data/explainer/**` and `runs/usage/M02-T03/**` in the AIRR kit folder; `.plan/work/M02-T03/result.md`

### M02-T05 Validate and record the explainer acceptance bar
- Precondition: M02-T04 done.
- Proposes the bar (default: on the clean held-out set zero verdict contradictions, zero invented values, at least 99 per cent deterministic pass, and a judge preference over the template whose lower noise-band bound is above 50 per cent) and validates it: the template explainer scored against itself sits at parity and fails the preference part, planted bad outputs fail. Adds the `bar` subcommand.
- The orchestrator records the bar as `## DEC-nnn Explainer acceptance bar` (approver orchestrator, shown to G at the budget look) before any M03 run.
- Saves the scheduler accounting export of its jobs under `runs/usage/M02-T05/`. Writes `bar-validated: yes` and `gpu-hours: judging <used>` under `### Findings`.
- verify: `grep -qx 'bar-validated: yes' .plan/work/M02-T05/result.md && "$AIRR_KIT/bin/kit-check" bar --result .plan/work/M02-T05/result.md`
- files: `judging/bar/**`, `checks/bar.py`, `checks/SHA256SUMS` (its own check modules' lines only, DEC-003; M02-T02, M02-T04 and M02-T05 never hold it at the same time) and `runs/usage/M02-T05/**` in the AIRR kit folder; `.plan/work/M02-T05/result.md`
