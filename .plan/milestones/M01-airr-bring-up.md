---
id: M01
name: airr-bring-up
weight: 15
status: planned
---
# M01 airr-bring-up
Track B. Research tasks: the only repository output is `.plan/work/<id>/result.md`; code, data and run records live in the plan v4 folder of the development kit (outside the repository, created by M01-T01, called the AIRR kit folder below and named `$AIRR_KIT` in the shell). No GPU-hour is spent before G approves the plan v4 scope (DEC-001). Every run task writes `gpu-hours: <stage> <used>` (cumulative, failed and retried jobs included) on its own line under `### Findings` and saves the scheduler accounting export of its jobs under `runs/usage/<task-id>/` in the AIRR kit folder, which its `files:` line authorises; the caps come only from the master-plan budget table. Every measurement is reproduced by `kit-check` (ARCHITECTURE.md kit verification interface).

## Goal
The Isambard-AI allocation is reachable through G's login, a runbook records the system's real facts instead of the old cluster's assumptions, a standalone trainer and the `kit-check` verifier in the AIRR kit folder run without the module 1.4.0 removed, and one reproduction of the v10 build on Isambard-AI scores inside the recorded gates, which proves the pipeline end to end.

## Definition of Done
- [x] The runbook and the porting list exist in the AIRR kit folder, and every unknown is listed with the check that settles it: `grep -qx 'runbook: written' .plan/work/M01-T01/result.md && test -s "$AIRR_KIT/runbook/README.md"`
- [x] Review: G ran the Isambard-AI login, and the route workers use after it (or the one command per stage G runs when no worker route exists) is recorded: `grep -qx 'login: confirmed' .plan/work/M01-T02/result.md`
- [x] The eight unknowns are checked on the system and written into the runbook (compute-node internet, login-node egress, Python and CUDA driver, aarch64 torch, PEFT, transformers and bitsandbytes, Apptainer images, storage quotas and purge rules, data route in and out): `grep -qx 'unknowns-checked: 8/8' .plan/work/M01-T02/result.md`
- [x] The standalone trainer passes its offline self-test and imports nothing from `auditex` or `azure_tenant_audit`, reproduced by the verifier: `"$AIRR_KIT/bin/kit-check" selftest --result .plan/work/M01-T03/result.md`
- [x] The qualification job passes on a GH200 node (DDP check, a short LoRA step, checkpoint save and reload, scoring smoke), with its scoring smoke reproduced: `grep -qx 'qualification: pass' .plan/work/M01-T04/result.md && "$AIRR_KIT/bin/kit-check" score runs/qualification --result .plan/work/M01-T04/result.md`
- [x] The v10 reproduction is measured and recomputed from the saved predictions, and its outcome is accepted by G (amended by DEC-011: four runs scored 393, 393, 387 and 372 of 435 quantised against the bar of 400; the pipeline is accepted as qualified and the recorded 403 is recorded as not reproduced): `grep -q '^reproduction: ' .plan/work/M01-T05/result.md && grep -q '^## DEC-011 ' .plan/DECISIONS.md && "$AIRR_KIT/bin/kit-check" score runs/v10-repro --result .plan/work/M01-T05/result.md`
- [ ] GPU-hours per stage, every job included, stay within the caps G approved (ARCHITECTURE.md budget binding): ``for s in bringup repro; do row=$(grep "^| $s | " .plan/master-plan.md) && c=$(printf '%s\n' "$row" | awk -F'|' '{gsub(/[ ,]/,"",$4); print $4}') && printf '%s\n' "$c" | grep -qE '^[0-9]+$' && d=$(printf '%s\n' "$row" | awk -F'|' '{gsub(/ /,"",$5); print $5}') && grep -A8 "^## $d " .plan/DECISIONS.md | grep -q '^- approver: G' && grep -A8 "^## $d " .plan/DECISIONS.md | grep -q '^- status: approved' && e=0 && for t in $(printf '%s\n' "$row" | awk -F'|' '{gsub(/,/," ",$3); print $3}'); do v=$(sed -n "s/^gpu-hours: $s \([0-9][0-9]*\(\.[0-9][0-9]*\)\{0,1\}\)\$/\1/p" ".plan/work/$t/result.md" | head -1) && test -n "$v" && e="$e+$v" || exit 1; done && test "$(printf 'r=0\nif (%s <= %s) r=1\nr\n' "$e" "$c" | bc)" = 1 || exit 1; done && "$AIRR_KIT/bin/kit-check" usage --results .plan/work``
- [ ] Review: a reviewer of the other vendor from the run tasks' author reruns `kit-check all` on the recorded artefacts and checks the checkpoint and build hashes and the scheduler accounting on the system (ARCHITECTURE.md kit verification interface): `grep -qE '^[[:space:]]*(summary: )?verdict: approve' .plan/work/REV-M01-kit/result.md`

## Tasks
| id | title | owner | size | tags | status |
|---|---|---|---|---|---|
| M01-T01 | Write the Isambard-AI runbook and porting list in a new AIRR kit folder | terra | S | - | done |
| M01-T02 | Bring up Isambard-AI after G's login and check the unknowns on the system | terra | S | debug | done |
| M01-T03 | Build a standalone trainer, scorer and the kit-check verifier in the AIRR kit folder | codex | M | - | done |
| M01-T04 | Build the environment and pass the qualification job on Isambard-AI | terra | M | debug | done |
| M01-T05 | Reproduce the v10 build on Isambard-AI | terra | M | debug | done |

## Acceptance criteria
### M01-T01 Write the Isambard-AI runbook and porting list in a new AIRR kit folder
- Creates the AIRR kit folder (a new dated folder of the development kit, outside the repository) with a README naming its purpose, the plan v4 task ids and the `AIRR_KIT` convention.
- The runbook adapts the old cluster chains (qualify, real, score; round-4, G4 and v10 stage scripts) to Isambard-AI: the nine porting items in `.plan/work/INV4-kit-chains/result.md` each map to a runbook step or are marked not needed, with the reason; the facts from `.plan/work/PASS-airr/result.md` and `.plan/work/INV4-bases/result.md` are marked unverified until M01-T02 checks them.
- G's login is a named step with what G types and what workers can do afterwards; base snapshots are fetched straight onto Isambard-AI project storage, never onto the workstation; held-out and sealed rows stay off public storage; how the scheduler accounting export for `kit-check usage` is taken.
- Writes `runbook: written` on its own line under `### Findings` in `result.md`. No GPU time, no login, no download.
- verify: `grep -qx 'runbook: written' .plan/work/M01-T01/result.md && test -s "$AIRR_KIT/runbook/README.md"`
- files: `runbook/**` and `README.md` in the AIRR kit folder; `.plan/work/M01-T01/result.md`

### M01-T02 Bring up Isambard-AI after G's login and check the unknowns on the system
- Preconditions: DEC-001 approved; M01-T01 done; G has run the login (the orchestrator asks G when the task is ready, not before).
- Checks each of the eight unknowns in the Definition of Done on the system with a recorded command and its output summary; updates the runbook with the real values; records the allocation balance shown by the system, the project storage paths' purge rules and whether `workq` limits match the docs.
- Records how long a login lasts and how workers submit jobs after it; if workers cannot, the runbook gives G one command per stage. Saves the scheduler accounting export for its jobs under `runs/usage/M01-T02/`.
- Writes `login: confirmed`, `unknowns-checked: 8/8` and `gpu-hours: bringup <used>` on their own lines under `### Findings` (interactive checks only, no training).
- verify: `grep -qx 'login: confirmed' .plan/work/M01-T02/result.md && grep -qx 'unknowns-checked: 8/8' .plan/work/M01-T02/result.md && grep -qE '^gpu-hours: bringup [0-9]+(\.[0-9]+)?$' .plan/work/M01-T02/result.md`
- files: `runbook/**` and `runs/usage/M01-T02/**` in the AIRR kit folder; `.plan/work/M01-T02/result.md`

### M01-T03 Build a standalone trainer, scorer and the kit-check verifier in the AIRR kit folder
- Ports `src/auditex/model_training.py`, `scripts/score-adapter-checkpoints.py`, `scripts/split-oracle-cases.py` and `scripts/run-model-benchmark.py` from tag `v1.3.0` into a self-contained `trainer/` package in the AIRR kit folder; nothing imports `auditex` or `azure_tenant_audit` (the value rules and template explainer, where needed, come from the released 1.4.0 wheel with its gated sha256, never from a repository checkout).
- The base model is a required argument (no stale `Qwen/Qwen3.8-27B` default); checkpoint selection follows the recorded `SELECTION_RULE` (applicability errors before strict score) and the trainer does not also select on eval loss (`load_best_model_at_end` off, or the conflict resolved and stated).
- The v10 recipe is read from the v10 run's own recorded config in the kit and written into the trainer's preset, with its source cited in `result.md`.
- Builds `bin/kit-check` with the subcommand discovery, the `--result` comparison and the `SHA256SUMS` check, and the `selftest`, `score` and `usage` subcommands as ARCHITECTURE.md fixes them; this interface is frozen before any run task starts. Each subcommand has an offline test that a tampered artefact or a result line that disagrees with the recomputed figure makes it fail.
- An offline self-test trains a tiny model on a tiny synthetic pack on CPU, saves and reloads a checkpoint and scores it; pins match the old environment file unless M01-T02 shows a needed change.
- Writes `trainer-selftest: pass` and `auditex-imports: 0` on their own lines under `### Findings`.
- verify: `"$AIRR_KIT/bin/kit-check" selftest --result .plan/work/M01-T03/result.md`
- files: `trainer/**`, `bin/**`, `checks/{selftest,score,usage}.py` and `checks/tests/**` in the AIRR kit folder; `.plan/work/M01-T03/result.md`

### M01-T04 Build the environment and pass the qualification job on Isambard-AI
- Preconditions: M01-T02 and M01-T03 done.
- Builds the aarch64 environment the runbook chose (Apptainer image or project venv), stages the Ministral 3 8B base snapshot on project storage at a pinned revision, and runs the qualification job: DDP check, a short LoRA step, checkpoint save and reload, and the scoring smoke, whose predictions are copied back to `runs/qualification/` with `SHA256SUMS`.
- Records the exact torch, CUDA, transformers, PEFT, TRL and llama.cpp versions in the runbook.
- Writes `qualification: pass` and `gpu-hours: bringup <used>` on their own lines under `### Findings`.
- verify: `grep -qx 'qualification: pass' .plan/work/M01-T04/result.md && "$AIRR_KIT/bin/kit-check" score runs/qualification --result .plan/work/M01-T04/result.md`
- files: `env/**`, `runbook/**`, `runs/qualification/**` and `runs/usage/M01-T04/**` in the AIRR kit folder; `.plan/work/M01-T04/result.md`

### M01-T05 Reproduce the v10 build on Isambard-AI
- Precondition: M01-T04 done.
- Trains Ministral 3 8B with the recorded v10 recipe on oracle pack v10, selects the checkpoint by the recorded rule, quantises to Q5_K_M with llama.cpp and scores alone (no rule pre-check) on frozen test-v7; the predictions, the selection log and the build's sha256 go to `runs/v10-repro/` with `SHA256SUMS`.
- Writes `reproduction: pass` on its own line under `### Findings` only when strict is at least 400 of 435, applicability errors are at most 5 and the quantised build passes the recorded G4 parity rule; writes `strict: <n>/435`, `applicability-errors: <n>`, `build-sha256: <64 hex>` and `gpu-hours: repro <used>`, and compares the score with the recorded 403 of 435.
- The build stays on project storage; any copy off the system follows the storage routing (G's download ruling: no telling or asking first, whatever the size).
- verify: `grep -qx 'reproduction: pass' .plan/work/M01-T05/result.md && "$AIRR_KIT/bin/kit-check" score runs/v10-repro --result .plan/work/M01-T05/result.md`
- files: `runs/v10-repro/**` and `runs/usage/M01-T05/**` in the AIRR kit folder; `.plan/work/M01-T05/result.md`
