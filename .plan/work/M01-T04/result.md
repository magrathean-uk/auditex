## RESULT M01-T04
status: done
summary: The qualification job passes on a four-GPU node: runtime report, DDP check, 40-step LoRA run on Ministral 3 8B, checkpoint reload, and scoring smoke (16 of 16).
summary: The environment is a project venv on Python 3.12.16 with the trainer pins and torch 2.14.1+cu126, plus a CPU-only llama.cpp build.
summary: The base is the v10 base of record at revision f6fae9795746f63c9be8344932f01275f3c63734, fetched on the system with all hub hashes matched.
summary: Six jobs used 0.69 GPU-hours. One was cancelled unstarted, three failed fast, and one weak smoke learnt nothing. No job is left on the system.
changes: kit/20261111-airr-v4/env/** (settings.sh, build-env.sh, qualify.sbatch, fetch_snapshot.py, ddp_check.py, reload_check.py, runtime_report.py, make_qual_cases.py, requirements-gpu.txt); kit/20261111-airr-v4/runbook/README.md (section 8 added); kit/20261111-airr-v4/runs/qualification/**; kit/20261111-airr-v4/runs/usage/M01-T04/**; .plan/work/M01-T04/notes.md; project store only on the system. No repository edits.
verification: `grep -qx 'qualification: pass' <scratch copy of result.md> && kit-check score runs/qualification --result <scratch copy>`, run from a scratch folder under $TMPDIR - pass (exit 0)
verification: `kit-check usage --result <scratch copy>` - pass (0.69 GPU-hours recomputed from 6 jobs)
verification: `bash -n` over env/*.sh and qualify.sbatch, and a compile of env/*.py - pass; `kit-check selftest` not rerun (trainer untouched; machine load about 12)
risks: The trainer reads cache snapshot files with O_NOFOLLOW but the hub cache stores symlinks (defect in `trainer/model_training.py`). `fetch_snapshot.py` works around it with hard links, so M01-T05 must use that script, and the trainer owner should fix the defect.
risks: 4-GPU normal-queue jobs waited over 50 minutes with no idle node. The same job started in seconds with `--reservation=interactive`, which the docs bill at 1.5x. The accounting export and `gpu-hours` count raw elapsed time, so the allocation may be debited more.
risks: Login nodes cap a user at 4 GiB of memory. No CUDA build of llama.cpp and no gguf converter package exist yet (CPU-only llama.cpp build); M01-T05 may need them.
questions_for_g: none
### Findings
qualification: pass
gpu-hours: bringup 0.69
strict: 16/16
applicability-errors: 0
selected: checkpoint-10
torch: 2.14.1+cu126 (CUDA 12.6 build, cuDNN 9.10.02, NCCL 2.29.3, driver 580.178.04)
transformers: 5.20.1
peft: 0.21.2
trl: 1.16.0
llama.cpp: b12284 (commit 9e9619d030bbe6b584d826a0a6cf06e38251f52b, CPU-only build)
base-snapshot: mistralai/Ministral-3-8B-Instruct-2512-BF16 f6fae9795746f63c9be8344932f01275f3c63734
ddp-check: pass (4 ranks, NCCL all-reduce 6.0, weights identical on all ranks)
checkpoint-reload: pass (max difference 0.0 against the saved adapter, 22.2 against the bare base)
notes: .plan/work/M01-T04/notes.md; runbook section 8 in kit/20261111-airr-v4/runbook/README.md
