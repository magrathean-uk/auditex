## RESULT M01-T05
status: done
summary: All four DEC-009 runs trained, scored and built. Mean quantised strict is 386.25 of 435, below the bar of 400, so the reproduction fails.
summary: Run 4 has 14 applicability errors against a limit of 5. The original v10 checkpoint scores 402 through this kit's scorer, so the shortfall is in the trained weights, not the scorer.
summary: 14 jobs used 12.465 GPU-hours (raw elapsed time times GPUs), well inside the 48-hour cap. Nothing is left running on the system.
changes: kit `runs/v10-repro/**` (top level is run 3, plus `run-1` to `run-4`, `runs.json`, `SHA256SUMS`); kit `runs/usage/M01-T05/**` (accounting-repro.psv, jobs.json, SHA256SUMS); kit `runbook/README.md` section 10 per brief step 6. Notes are in `.plan/work/M01-T05/notes.md`.
verification: `kit-check score runs/v10-repro --result` against a scratch copy of the result under `$TMPDIR` passed. `kit-check usage --result` against the same copy passed (12.465 GPU-hours over 14 jobs). The verify command's `grep -qx 'reproduction: pass'` fails by design, because the result is `fail`. `kit-check all` on the scratch copy fails only because that copy has no M01-T04 result file.
risks: (1) The 21-row bf16 spread across seeds (376 to 397) is far above the 6 rows DEC-009 assumed. (2) `score` recomputes only run 3, the nearest-mean run. The other three runs, the mean, the sd and the reproduction line are not recomputed by any check; they are in `runs.json`. (3) The interactive reservation is documented as billed at 1.5x. The accounting export counts raw hours, so the allocation may be debited up to 1.5x more for jobs 8309703 and 8313957, the two reservation trainings.
questions_for_g: none
### Findings
run 1: seed 42 selected checkpoint-450 validation 408/531 bf16 395/435 quantised 393/435 applicability-errors 3
run 2: seed 42 selected checkpoint-400 validation 441/531 bf16 397/435 quantised 393/435 applicability-errors 3
run 3: seed 43 selected checkpoint-350 validation 409/531 bf16 385/435 quantised 387/435 applicability-errors 0
run 4: seed 44 selected checkpoint-400 validation 427/531 bf16 376/435 quantised 372/435 applicability-errors 14
mean-strict: 386.25
spread: min 372 max 393 sd 9.91
reproduction: fail
strict: 387/435
applicability-errors: 0
build-sha256: 66622f9db374d799ee53079f32c94bbded05b355e3ea1abf14b2f5afd584c92c
bf16-strict: 385/435
bf16-applicability-errors: 0
val-strict: 409/531
val-applicability-errors: 0
val-selected: checkpoint-350
gpu-hours: repro 12.465
parity-on-run-3: strict at least 400 fails (387), within 10 of own bf16 passes (385), merged and GGUF token ids 435/435 equal, GGUF hash matches the benchmark's.
sd: sample standard deviation (population 8.58). Run 3 is nearest the mean. Against the recorded 403, runs 1 to 4 are 10, 10, 16 and 31 rows lower.
original-checkpoint diagnostic: the archived v10 checkpoint-500 scores 402/435 bf16 with 0 applicability errors through this scorer (recorded 404), and the packs' train, validation and test files are byte-equal to the recorded v10 pack.
comparison 1: effective batch 8 (1 per device x 2 accumulation x 4 devices) and 537 steps in all four runs. The recorded v10 trainer state shows 537 steps and epoch 0.9311 at step 500, which gives the same effective batch 8; it does not record the device count, so 4 devices is inferred from that.
comparison 2: logged train loss over 100 common steps correlates 0.9999 with the recorded run in runs 1 and 2 (mean abs difference 0.0006), so the batch order is the same; seeds 43 and 44 were not compared. Run 2 does not equal run 1 bit for bit: all 12 adapter hashes differ, final adapters 0ef39d9a... against 7fcbdc82...
verifier limits: `score` accepted a `fail` result and extra per-run lines. It recomputes one run folder only (the run at `runs/v10-repro`), so the three other runs cannot be recomputed there. A `measures.json` in a sub-folder would make `kit-check all` fail discovery, because the run must sit at exactly `runs/v10-repro`. Nothing was patched.
queue: trainings 8314423 and 8314424 started within seconds on the normal queue; all scoring and build jobs started within seconds. Earlier: 8308639 waited 15 minutes and was cancelled. Interactive reservation was used for 8309703 and 8313957.
job ids: trains 8309703 (run 1), 8313957 (run 2), 8314423 (run 3), 8314424 (run 4); scores 8310604, 8314431, 8314437, 8314439; builds 8313778, 8314435, 8314438, 8314440; diagnostic 8313832; cancelled 8308639.

orchestrator correction (11 Nov 2026, from REV-M01-kit against the scheduler's accounting): job 8313957 (run 2 training) ran on the normal queue, not the interactive reservation; only 8309703 (run 1 training) used the reservation in this task. Reservation GPU-hours for the repro stage are 0.918, not the figure implied by two reservation trainings. The task caps in the briefs (48 and 96) sit under the stage caps in the budget table (64 and 128).
