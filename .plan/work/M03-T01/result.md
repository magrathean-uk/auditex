## RESULT M03-T01
status: partial
summary: Round 1 (set up and submit) finished; partial by design because the seed and judge jobs are still running or queued, so there is no base-comparison or base-pick yet. Qwen 4 is not on the Qwen org hub, so the four named bases were pinned and fetched on the system; load checks pass for 8B, 14B and Gemma 4 31B, and the Qwen3.8-27B fetch is slow and still running.
  The recipe family and the selection rule were written in kit runbook section 13 before any seed job. The smoke job 8376179 (8B) ran train, generate, frozen checks, judge, the bar's evaluate_seed and the selection end to end.
  Projection is about 260 GPU-hours against the 1,024 cap, so there is no cut: three seeds and two epochs for every base. 24 seed jobs were submitted (a prep and a judge job per seed). All six Ministral prep jobs COMPLETED, their judge jobs are running, and the Gemma prep jobs are generating outputs.
  Completion is blocked for now: kit-check score has no explainer score kind (checks/score.py knows only structured-v1), so the owner of checks/ must add one before the verify can pass.
changes: kit runbook/README.md (new section 13); kit runs/base-comparison/scripts/{fetch-base.sbatch, load_check.py, explainer_stage.py, seed.sbatch, submit-seeds.sh, evaluate.py}; kit runs/base-comparison/smoke1/** with SHA256SUMS (no measures.json); kit runs/usage/M03-T01/{accounting-basecmp.psv, accounting-basecmp-run2.psv, jobs.json, SHA256SUMS}; .plan/work/M03-T01/{notes.md, progress.md}. On the system: the kit copy gained data/explainer train, validation and SHA256SUMS (hashes equal) and the scripts; runs go in the plan's runs folder. No repository edits.
verification: kit-check usage --result <scratch copy at $TMPDIR/m03t01/work/M03-T01/result.md>: pass (13.7034 GPU-hours, 10 attempts)
verification: the brief's verify on the same scratch copy: the M02-T06 grep passes; the base-comparison grep fails (expected for partial); kit-check score fails with "missing artefact: SHA256SUMS" (no run folder until collection)
verification: data manifest checked on the workstation and the system (5ec3b695...4aa4, train bbd768e5..., validation d3887487...); judge, prompt, checks tree and trainer hashes on the system equal the kit's; bash -n and py_compile on the scripts pass
risks: Qwen3.8-27B downloads at about 50 MB/s without a hub token; follow-on fetch 8376389 (afterany) covers a timeout of 8376156; if its load check fails, the q27 jobs stay pending and need cancelling at collection.
risks: Gemma 4 loads as Gemma4ForConditionalGeneration (whole multimodal model), so its LoRA all-linear targets may include vision projections; the judge is about 6-7 s per judgement, so each judge job takes about 4-5 h.
risks: The 8B smoke ran on the interactive reservation (billed 1.5x by the docs); every seed job runs on the normal queue.
questions_for_g: none
### Findings
qwen4-check: no Qwen 4 open weights on the Qwen organisation's hub (org search on the system); not a candidate this round
candidate: mistralai/Ministral-3-8B-Instruct-2512-BF16@f6fae9795746f63c9be8344932f01275f3c63734 (apache-2.0, load check pass)
candidate: mistralai/Ministral-3-14B-Instruct-2512-BF16@3cea74c1ebaf5ce5f5a2553de470e2ceab825142 (apache-2.0, fetched, load check pass)
candidate: google/gemma-4-31B-it@842da3794eaa0b77d5f08bae87a17459d91ff475 (apache-2.0, fetched, load check pass)
candidate: Qwen/Qwen3.8-27B@37561816e66b5b9153b1b64c10968c18c1e6f4a0 (apache-2.0, fetch running: 8376156, follow-on 8376389)
recipe: kit runbook section 13; v10 preset bf16 LoRA, 2 epochs (686 steps), checkpoints 171/342/513/684/686, seeds 42 43 44 for every base
selection-rule: kit runbook section 13; validation only; floor, then preference, then flagged share, then step; noise band = the top base's seed range; EU-first inside the band
smoke: 8376179 COMPLETED, 802 s on 4 GPUs (0.8911 GPU-hours); checks 24/24 and 21/24; 90 judgements; evaluate_seed and selection ran
projection: about 260 GPU-hours for 4 bases x 3 seeds (judging about 210), under 800, no cut
seed-jobs-prep: 8376248 8376250 8376252 (m8, COMPLETED) 8376254 8376256 8376258 (m14, COMPLETED) 8376260 8376262 8376264 (g31, running) 8376266 8376268 8376270 (q27, afterok 8376389)
seed-jobs-judge: 8376249 8376251 8376253 8376255 8376257 8376259 8376261 8376263 8376265 8376267 8376269 8376271 (afterok on their prep)
fetch-jobs: 8376154 8376155 8376157 COMPLETED (CPU only); 8376156 running, 8376389 pending (CPU only)
validation-checks-pass: Ministral 8B and 14B seeds pass the frozen checks on 257-267 of 267 outputs per checkpoint
base-comparison: not complete (round 1 of 2; collection pending)
gpu-hours: basecmp 13.71
