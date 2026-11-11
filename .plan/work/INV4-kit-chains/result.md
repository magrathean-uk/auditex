## RESULT INV4-kit-chains
status: done
summary: Inventory of the kit's GH200 Slurm chains (qualify/real/score, round-4, G4, v10 stage), environment pins, base snapshot, data routes, ledger (25.45 of 100 node-hours), and a porting list. Nothing was run on a cluster; no downloads, no tenant contact.
summary: The kit is a symlink target on the external volume, so the ~/dev/machine path works.
summary: Full detail and line references are in .plan/work/INV4-kit-chains/notes.md (104 lines).
changes: created .plan/work/INV4-kit-chains/notes.md only
verification: bash -n on 8 bash scripts pass; g4-harvest.sh fails only because it is zsh (expected); zsh -n on 4 v10 scripts pass; round4-chain.sh --dry-run printed 4 templates; g4-chain.sh --dry-run printed 14 lines (exit status not captured); 13 referenced helpers exist; rg confirms 36 train_lora.py shims; 11 shell commands used of 15
risks: Dry-run output was counted, not inspected; the claim that it wrote nothing rests on the script header. Ledger uses elapsed x nodes and jutil billing is unreconciled. Python version and llama.cpp commit on the node are not recorded in the kit.
questions_for_g: none

### Findings

1. exists
- Stage runners: kit/20261023-jupiter-deploy/run-qualify.sh, run-real.sh, run-score.sh, run-pilot.sh (copies in kit/20261022-jupiter-payload-v2/).
- Job scripts: kit/20261023-jupiter-deploy/env/qualify-jupiter.sbatch (1 node, 4 GPU, 288 CPU, 01:30); env/score-checkpoints.sbatch; env/serving-check.sbatch; env/benchmark-gguf.sbatch. Per-pack training sbatch: kit/<pack>/jupiter-auditex.sbatch.
- Helpers: env/submit-lib.sh, env/jupiter-env-setup.sh, env/bootstrap-jupiter-venv.sh, env/stage-base-snapshot.sh; tools/qualify-runtime.py, assemble-qualification.py, check-ddp.py, plan-wall-time.py, pack-results.py, fetch-from-civo.sh (kit/20261023-jupiter-deploy/tools/).
- Round 3: kit/20261028-round3/round3-chain.sh. Round 4: kit/20261029-round4/round4-chain.sh (163 lines), tools/r4-harvest.sh.
- G4 small tier: kit/20261030-g4-8b/g4-chain.sh (424 lines), g4-harvest.sh (zsh, 251 lines).
- v10 stage: kit/20261030-round5-v10/tools/v10-stage.sh, v10-launch.sh, v10-unpack.sh, v10-harvest.sh.
- Held build: kit/20261104-civo-pull/ (RUNBOOK.md, not run). gguf/model-Q5_K_M.gguf 6,058,747,104 B; parts part-00 4,294,967,296 B and part-01 1,763,779,808 B; SHA256SUMS 268 B; adapter tar 373,913,600 B.
- Pins: kit/20261023-jupiter-deploy/env/requirements-jupiter-cu126.txt (torch 2.14.1+cu126, transformers 5.20.1, trl 1.16.0, peft 0.21.2, accelerate 1.15.0, datasets 5.1.0, huggingface_hub 2.2.0); requirements-jupiter-cu13.txt (torch 2.14.1 from PyPI, CUDA 13.0.3 wheels).
- Mac freeze: kit/20261023-jupiter-deploy/env/mac-qualification-freeze.txt.
- Wheels: kit/wheels/ (auditex 1.2.1, 1.2.2.dev1, 1.2.2.dev2; 1.45 to 1.48 MB); payload copies in kit/20261019-jupiter-payload/wheels/ (1.0.0) and kit/20261022-jupiter-payload-v2/wheels/ (1.0.0).
- Base snapshot: public model hub, pinned revision, 32 files, 55.59 GB (kit/20261023-jupiter-deploy/env/stage-base-snapshot.sh:4); manifest env/base-snapshot-files.json. env/base-small-blobs/ holds 13 files, about 10.3 MB.
- Aarch64: kit/20261018T185506Z-validated/training-pack/jupiter-auditex.sbatch:10 requires an Arm64 env setup; flash-linear-attention and causal-conv1d built on aarch64 (kit/20261020-training-plan/TRAINING-PLAN.md:303).

2. works
- bash -n passes: round4-chain.sh, g4-chain.sh, run-qualify.sh, run-real.sh, run-score.sh, jupiter-env-setup.sh, submit-lib.sh, round3-chain.sh. zsh -n passes: the four v10 scripts.
- round4-chain.sh --dry-run ministral3-8b (ROUND4_STAMP and SCORE_STEPS set): 4 submit templates. g4-chain.sh --dry-run: 14 lines.
- rg over kit: all 36 train_lora.py are 6-line shims; line 3 is `from auditex.model_training import training_main`.
- Qualification report kit/20261023-jupiter-deploy/results-20261025/second-run/f-qualify-pilot-pack-2497772/qualification-report.json: torch 2.14.1+cu130, CUDA 13.0, GH200 120GB, capability 9.0, runtime_qualified true, local_smoke_only false (rg).
- Freeze pins match the requirements files (rg, mac freeze lines 34-58).
- Symlink: ~/dev/machine/work/auditex-data points to the external volume (ls -ld).

3. broken
- P5 model-pass serve job timed out at 51:27, about 0.86 node-hours (kit/20261027-ship-plan/PLAN-SHIP.md, 30 Oct 22:25 entry).
- kit/20261030-g4-8b/PACKAGE-SHA256SUMS.new is 0 bytes (stale).
- kit/20261104-civo-pull/RUNBOOK.md:12 says parts 5.98 GB; the parts sum to 6.06 GB.

4. dead candidates
- Superseded: kit/20261029-oracle-pack-v8/superseded-capped-70/, superseded-precedence-20261029/; kit/20261030-oracle-pack-v10/superseded-round1/, superseded-round2/. Still referenced from kit/20261031-session-reviews/ (rg), so not fully dead.
- Payload copies: kit/20261019-jupiter-payload/ and kit/20261022-jupiter-payload-v2/ duplicate run-*.sh and tools. The 20261023 freeze still names the 20261019 wheel, so that copy is referenced.
- kit/20261031-v11-plan/: name suggests V11, memory says cancelled; kit content not checked.
- Abandoned TODOs: not searched.

5. contradictions
- kit/20261020-training-plan/TRAINING-PLAN.md:124 says 100-300 GPU-hours (25-75 node-hours); kit/20261027-ship-plan/PLAN-SHIP.md:94 sets 100 node-hours. TRAINING-PLAN is stale.
- kit/20261028-round3/RESULTS-round3.md:11 says 13.9 of 25 remain; PLAN-SHIP.md:72 says the arithmetic is wrong (25 - 18.39 = 6.61).
- kit/20261029-round4/round4-chain.sh:3 and :52 say v8 pack; round 4 ran v9 (PLAN-SHIP.md:84).
- kit/20261023-jupiter-deploy/env/jupiter-env-setup.sh:35 claims CUDA 13.0.0 and Python 3.13 from a changelog; unverified here.

6. open questions
- Python patch version and module list on the cluster: a node.log or module-list file in a qualification folder (none in the listings read).
- llama.cpp commit actually built: serving-check JSON under kit/20261030-g4-8b/results-20261030T0345Z/serving-check/ (not read).
- Whether develbooster bills: PLAN-SHIP.md:72; settle with kit/20261030-g4-8b/results-20261030T0345Z/reports/cpuquota-*.txt.
- session-env.sh that the chains source lives outside the kit.
- Porting to an aarch64 GH200 Slurm system with Apptainer and a 24 h queue (inferred, untested):
  1. Replace the site module and jutil calls (jupiter-env-setup.sh:19, :37; round4-chain.sh:31-32).
  2. Replace the /e/project1 and /e/scratch defaults (jupiter-env-setup.sh:5-6; round4-chain.sh:28); the AUDITEX_JUPITER_ROOT and _SCRATCH overrides exist (:13).
  3. Replace hard-coded booster and develbooster partitions (run-qualify.sh:20; run-score.sh:33).
  4. Wall times fit 24 h; the 120-minute reservation rule (run-real.sh:12) needs the target's own partition names.
  5. Add Apptainer binds for HF_HOME, scratch, packs and llama.cpp; every step runs PYTHON_BIN from the venv (jupiter-env-setup.sh:40).
  6. Build the Arm64 kernels for flash-linear-attention and causal-conv1d on the target node; the cu126 wheel index is external (requirements-jupiter-cu126.txt:2).
  7. Login-node egress is assumed for base staging and object-store transfers; compute nodes are offline (jupiter-env-setup.sh:48).
  8. The durable root must not be scratch (jupiter-env-setup.sh:31).
  9. Replace the presigned object-store and SSH route used by the v10 scripts.
- Neighbour area: kit/20261027-ship-plan/tree/ and kit/20261031-dummy-tenant/ hold tooling copies; one file (resume-job.sh under the ship-plan tree) is unreadable (permission denied).
