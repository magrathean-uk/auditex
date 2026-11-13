## RESULT M03-T01
status: partial
summary: Round 2 (diagnosis) done; partial by design: seed and judge jobs still run, so no base-comparison or base-pick yet.
  The two Gemma 4 judge jobs ended early because few outputs passed the frozen checks: each judged every pair it had, in both orders. Gemma's template ends the generation prompt with an empty thought channel that TRL never trained, so the tuned model fell back to fenced JSON (not_strict_json).
  Fixed generate in runs/base-comparison/scripts/explainer_stage.py to feed the prompt tokens exactly as trained; proven unchanged for Ministral 8B/14B and Qwen3.8-27B on all 267 rows, so their outputs stand and the running q27 prep jobs run a no-op change.
  Cancelled 8376261, moved the superseded Gemma outputs and judgements outside the run folders, resubmitted the three Gemma prep and judge jobs as retries; regenerated checkpoint-171 passes 258/265/259 of 267 (was 0/69/0).
  Ministral judges run at 4.5-5.2 s per judgement (projected 6 s). Runbook section 13 gains Round 2, the DEC-033 tie sentence and the collecting steps.
changes: kit runs/base-comparison/scripts/{explainer_stage.py, submit-seeds.sh} (same sha256 on the system); kit runbook/README.md (section 13); kit runs/usage/M03-T01/{accounting-basecmp-run3.psv (new), jobs.json, SHA256SUMS}; .plan/work/M03-T01/{notes.md, progress.md}. On the project store: Gemma round 1 outputs moved to runs/m03t01/superseded-g31-context/. No repository edits.
verification: kit-check usage --result <scratch copy at $TMPDIR/m03t01/work/M03-T01/result.md>: pass (33.8167 GPU-hours, 18 attempts)
verification: the brief's verify on the same scratch copy: M02-T06 grep passes; base-comparison grep fails (expected for partial); kit-check score fails (no sealed run folder until collection)
verification: on the system, CPU tokenizer test over 267 validation rows x 4 bases (prompt ids old vs new): pass; frozen checks on the regenerated Gemma checkpoint-171 shards: 782/801 pass; py_compile and bash -n on the changed scripts: pass; Ministral raw judgements 7,406 rows, 0 duplicates
risks: Gemma 4 loads as Gemma4ForConditionalGeneration, so LoRA all-linear targets may include vision projections (unchanged from round 1).
risks: Qwen3.8-27B trains at 8.4-9 s per step (projected 2.6 s), so its prep and judge jobs end later (judge about 4.5 h after prep); time limits still hold.
risks: The six retries can be inventoried only after they end (kit-check usage needs a finished attempt); the collecting round adds them with retry_of in export run4.
questions_for_g: none
### Findings
qwen4-check: no Qwen 4 open weights on the Qwen organisation's hub (org search on the system); not a candidate this round
candidate: mistralai/Ministral-3-8B-Instruct-2512-BF16@f6fae9795746f63c9be8344932f01275f3c63734 (apache-2.0, load check pass)
candidate: mistralai/Ministral-3-14B-Instruct-2512-BF16@3cea74c1ebaf5ce5f5a2553de470e2ceab825142 (apache-2.0, fetched, load check pass)
candidate: google/gemma-4-31B-it@842da3794eaa0b77d5f08bae87a17459d91ff475 (apache-2.0, fetched, load check pass)
candidate: Qwen/Qwen3.8-27B@37561816e66b5b9153b1b64c10968c18c1e6f4a0 (apache-2.0, fetched by 8376156 and 8376389, load check pass)
recipe: kit runbook section 13; v10 preset bf16 LoRA, 2 epochs (686 steps), checkpoints 171/342/513/684/686, seeds 42 43 44 for every base; generation prompt = prompt tokens as trained (round 2)
selection-rule: kit runbook section 13; validation only; floor, then preference, then flagged share, then step; noise band = the top base's seed range, on an exact top tie the union (DEC-033); EU-first inside the band
smoke: 8376179 COMPLETED, 802 s on 4 GPUs (0.8911 GPU-hours); checks 24/24 and 21/24; 90 judgements; evaluate_seed and selection ran
projection: about 270 GPU-hours in all (Ministral judges about 87, Qwen3.8 prep and judge about 86, Gemma retries about 65), under the 1,024 cap, no cut
seed-jobs-prep: 8376248 8376250 8376252 (m8, COMPLETED) 8376254 8376256 8376258 (m14, COMPLETED) 8376260 8376262 8376264 (g31, COMPLETED, outputs superseded) 8376266 8376268 8376270 (q27, running)
seed-jobs-judge: 8376249 8376251 8376253 8376255 8376257 8376259 (Ministral, running) 8376261 (cancelled) 8376263 8376265 (COMPLETED, superseded) 8376267 8376269 8376271 (q27, pending on prep)
retry-jobs: g31 prep 8378092 8378098 8378102 (retry_of 8376260 8376262 8376264, running); g31 judge 8378095 8378100 8378104 (retry_of 8376261 8376263 8376265, pending on prep)
fetch-jobs: 8376154 8376155 8376156 8376157 8376389 COMPLETED (CPU only)
short-judge-cause: Gemma 4 generation prompt ended in an untrained empty thought channel; outputs fenced, not_strict_json; passing outputs per checkpoint s43 69/0/39/39/36, s44 0/0/6/4/3 of 267
judgements-complete: 8376263 and 8376265 judged every pair given (366 and 26 rows, both orders); not complete for the 267 rows, which the fix and retries cover
judge-rate: Ministral judges 4.5-5.2 s per judgement at 08:13 GMT (projected 6 s), about 3.3-3.8 h per job
fix-check: regenerated Gemma checkpoint-171 passes 258/265/259 of 267 (seeds 42/43/44); Ministral and Qwen3.8 prompts byte-identical to round 1
validation-checks-pass: Ministral 8B and 14B seeds pass the frozen checks on 257-267 of 267 outputs per checkpoint
base-comparison: not complete (round 2 of 3: diagnosis; collection pending)
gpu-hours: basecmp 33.82
