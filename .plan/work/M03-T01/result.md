## RESULT M03-T01
status: done
summary: Round 3 (collect and seal) done; base comparison complete, pick Gemma 4 31B at 842da3794eaa by the section 13 rule.
  All 36 jobs had ended (35 COMPLETED, 8376261 cancelled in round 2); none failed or timed out, so nothing was resubmitted. Nothing is left on the system.
  Copied 336 run artefacts to kit runs/base-comparison with sha256 matched on the system, in staging and in place; 0 duplicate judgement rows of 31,654; smoke1 moved to kit runs/base-comparison-smoke1.
  evaluate.py and kit-check score agree: only Gemma 4 31B and Qwen3.8-27B hold the floor on all three seeds; the Ministral bases miss it on 2 (8B) and 1 (14B) seeds, so no Mistral base is in the band and EU-first does not apply.
  Usage: export run4 (18 jobs), jobs.json 36 jobs with the six retries' retry_of; 235.67 of 1,024 GPU-hours.
changes: kit runs/base-comparison/{12 seed-run folders, evaluation.json, measures.json, SHA256SUMS, scripts/write_measures.py (new)}; kit runs/base-comparison-smoke1/ (moved from runs/base-comparison/smoke1); kit runs/usage/M03-T01/{accounting-basecmp-run4.psv (new), jobs.json, SHA256SUMS}; kit runbook/README.md (section 13, Round 3); .plan/work/M03-T01/{notes.md, progress.md}. No repository edits.
verification: brief verify command (M02-T06 grep, base-comparison grep, kit-check score runs/base-comparison --result) run from a scratch root under $TMPDIR holding a copy of these result lines and of M02-T06/result.md: pass, base-pick recomputed equal;
  kit-check usage --result <scratch copy>: pass, 235.6689 GPU-hours, 36 attempts; basecmp budget predicate (bc, cap 1,024, DEC-001) on the scratch copy: pass;
  sha256 of 336 copied files equal on the system, in staging and in the kit; checkpoint-hashes.txt rechecked on the system for all 12 runs: pass; path and name scan of the kit outputs: clean
risks: No base beats the template on validation: every selected checkpoint has win_pass false (preference 0.49-0.52, mostly ties), so the M03-T02 large runs start from parity, not from a lead.
  The Ministral floor misses are 1-3 wrong-verdict or wrong-value outputs of 267 per seed; the pick follows the written rule and depends on them.
  Gemma 4 loads as Gemma4ForConditionalGeneration (whole multimodal model), so LoRA all-linear targets may include vision projections; M03-T02 inherits this.
questions_for_g: none
### Findings
base-comparison: complete
base-pick: google/gemma-4-31B-it@842da3794eaa0b77d5f08bae87a17459d91ff475
gpu-hours: basecmp 235.67
rank: 1 Gemma 4 31B, 2 Qwen3.8-27B (floor on all seeds), 3 Ministral 3 8B, 4 Ministral 3 14B (floor missed on a seed)
noise-band: Gemma 4 31B seed range 0.4906-0.5150; inside: Gemma 4 31B, Qwen3.8-27B; no Mistral base inside, so the top base is picked (EU-first not applicable)
base-gemma-4-31b: mean preference 0.5006 (seeds 0.4906-0.5150); floor s42 pass, s43 pass, s44 pass; selected s42 checkpoint-513, s43 checkpoint-686, s44 checkpoint-513; mean flagged 0.0961
base-qwen3.8-27b: mean preference 0.4969 (seeds 0.4944-0.4981); floor s42 pass, s43 pass, s44 pass; selected s42 checkpoint-513, s43 checkpoint-513, s44 checkpoint-686; mean flagged 0.1199
base-ministral-3-8b: mean preference 0.5094 (seeds 0.5037-0.5150); floor s42 fail, s43 pass, s44 fail; selected s42 checkpoint-686, s43 checkpoint-342, s44 checkpoint-686; mean flagged 0.0861
base-ministral-3-14b: mean preference 0.5044 (seeds 0.5019-0.5094); floor s42 pass, s43 pass, s44 fail; selected s42 checkpoint-684, s43 checkpoint-684, s44 checkpoint-686; mean flagged 0.1149
floor-misses: m8-s42, m8-s44 and m14-s44 have 1-3 outputs of 267 with a wrong verdict or values (floor properties) at every checkpoint
qwen4-check: no Qwen 4 open weights on the Qwen organisation's hub (org search on the system at the start); not a candidate this round
candidate: mistralai/Ministral-3-8B-Instruct-2512-BF16@f6fae9795746f63c9be8344932f01275f3c63734 (apache-2.0, load check pass)
candidate: mistralai/Ministral-3-14B-Instruct-2512-BF16@3cea74c1ebaf5ce5f5a2553de470e2ceab825142 (apache-2.0, fetched, load check pass)
candidate: google/gemma-4-31B-it@842da3794eaa0b77d5f08bae87a17459d91ff475 (apache-2.0, fetched, load check pass)
candidate: Qwen/Qwen3.8-27B@37561816e66b5b9153b1b64c10968c18c1e6f4a0 (apache-2.0, fetched by 8376156 and 8376389, load check pass)
recipe: kit runbook section 13; v10 preset bf16 LoRA, 2 epochs (686 steps), checkpoints 171/342/513/684/686, seeds 42 43 44 for every base; generation prompt = prompt tokens as trained (round 2)
selection-rule: kit runbook section 13, unchanged; validation only; floor, then preference, then flagged share, then step; noise band = the top base's seed range (DEC-033 union on a top tie, not needed); EU-first inside the band
scored-folder: kit runs/base-comparison; measures.json kind explainer-validation-v1; SHA256SUMS 417 lines (345 files incl. 12 checkpoint-hashes.txt, 72 project: checkpoint lines)
judgements: 31,654 raw rows, 0 duplicates removed; every passing output judged in both orders; none for failing outputs
validation-checks-pass: 257-267 of 267 outputs per checkpoint for every base after the round 2 fix
smoke: 8376179 COMPLETED, 802 s on 4 GPUs (0.8911 GPU-hours); kept outside the scored folder in kit runs/base-comparison-smoke1
seed-jobs-prep: 8376248 8376250 8376252 (m8) 8376254 8376256 8376258 (m14) 8376266 8376268 8376270 (q27) COMPLETED; 8376260 8376262 8376264 (g31 round 1, COMPLETED, outputs superseded)
seed-jobs-judge: 8376249 8376251 8376253 (m8) 8376255 8376257 8376259 (m14) 8376267 8376269 8376271 (q27) COMPLETED; 8376261 (cancelled) 8376263 8376265 (COMPLETED, superseded)
retry-jobs: g31 prep 8378092 8378098 8378102 (retry_of 8376260 8376262 8376264), judge 8378095 8378100 8378104 (retry_of 8376261 8376263 8376265), all COMPLETED
fetch-jobs: 8376154 8376155 8376156 8376157 8376389 COMPLETED (CPU only)
short-judge-cause: round 1 Gemma 4 generation prompt ended in an untrained empty thought channel; fixed in round 2 (generation prompt as trained), retried
system-state: no job of this task running or pending; nothing left on the system but project-store files
