## RESULT M01-T02
status: done
summary: All eight unknowns were checked on the system, and the runbook (section 7, plus the step 1 and section 3/6 headers) now holds the real values. Two one-GPU jobs ran, 0.0192 GPU-hours, and the accounting export is saved. The shared connection held throughout, nothing is left running, and I cancelled nothing because no job was pending. The runbook line that told G about a large base snapshot first is gone.
changes: kit/20261111-airr-v4/runbook/README.md; kit/20261111-airr-v4/runs/usage/M01-T02/{accounting-bringup.psv,jobs.json,SHA256SUMS}; .plan/work/M01-T02/notes.md. No repository edits.
verification: ssh -O check showed the master running, before and after. Verify command on a scratch copy of the result under $TMPDIR: pass. `kit-check usage` on that copy: PASS (0.0192 recomputed, line 0.02). The real result file is written by the dispatcher.
risks: (1) The allocation balance is not visible on the system, only on the awards portal, so G must read it. (2) The trainer's numpy pin needs Python 3.12 or later, but the Cray Python module is 3.11, so build the environment on uv Python 3.12 or the system 3.13. (3) The whole scratch filesystem was about 1,300 files from its file-count limit, so use the project store only.
questions_for_g: none

### Findings
login: confirmed
unknowns-checked: 8/8
gpu-hours: bringup 0.02
login-lifetime: certificate valid for 12 hours (the system's docs); the shared connection is kept for 12 hours; after expiry, new connections are refused and G signs in again
worker-route: one shared connection reused by every ssh call with the worker config; `sbatch`, `squeue`, `sacct`, `rsync` and `scp` all work through it; no per-stage command for G while the certificate lasts
unknown-1-compute-node-internet: yes; a one-GPU job reached the model hub (a file fetch returned 200), the package index, the PyTorch index, the container registries and GitHub; no proxy set
unknown-2-login-node-egress: yes; same places, same replies
unknown-3-python-and-driver: login Python 3.6 (3.11 and 3.13 installed; Cray Python 3.11.7; uv Python 3.12.16 installs on the project store); compute node driver 580.178.04, CUDA 13.0 support, capability 9.0
unknown-4-aarch64-torch: pip wheel `torch==2.14.1+cu126` works; in a job cuda was available and a bf16 matmul ran; the environment is a project virtual environment, no container needed
unknown-5-peft-transformers-bitsandbytes: transformers 5.20.1, trl 1.16.0, peft 0.21.2, accelerate 1.15.0, datasets 5.1.0 install; bitsandbytes 0.50.2 aarch64 wheel ran a 4-bit forward pass; LoRA wrap ran; numpy 2.5.4 needs Python 3.12 or later; causal-conv1d has no wheel
unknown-6-apptainer: 1.5.3 on login and compute nodes; pull and build from Docker Hub work; an Ubuntu image ran with `--nv` showing the GPU; one Alpine image failed to mount
unknown-7-storage: project store 200 TiB and 51.2M files, kept to the project end date plus 30 days; scratch deleted after 60 days without access and effectively full by file count; home 101 GiB hard; node-local 512 GiB
unknown-8-data-route: rsync and scp both ways through the shared connection; a 200 kB file round-tripped with an identical sha256
allocation-balance: not shown by the scheduler (no `GrpTRESMins`; `sreport` shows 0 hours used); the balance is on the awards portal only
workq-limits-match-docs: yes for 1-day wall time and 256 running and 512 submitted jobs per user; the docs' 32-GPU cap (`32gpu_qos`) is not in the system's QOS list or on the association
interactive-billing: scheduler usage factor 1.0 on every QOS; the docs bill the interactive reservation at 1.5x
purge-rules: scratch 60 days since last access; project and home kept to the project end date, deleted after a 30-day grace; no backups; node-local removed at session end
accounting-export: `sacct -X -D -P --format=JobID,JobName,State,Start,End,ElapsedRaw,AllocTRES,NNodes -j <ids>` saved to `kit/20261111-airr-v4/runs/usage/M01-T02/accounting-bringup.psv`, with `jobs.json` and `SHA256SUMS`
jobs-run: 2 (41 s and 28 s elapsed, 1 GPU each); queue empty at the end
evidence: `.plan/work/M01-T02/notes.md`
