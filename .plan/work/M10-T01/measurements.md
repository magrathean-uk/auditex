# M10-T01 measurements: local runtime and models on this Mac

Answer design measured: DEC-119 (the model selects sentence ids and value references; Auditex renders every word).
The earlier free-prose prototype (prompt v1 to v4) is kept in `proto/` for history only; see "Prose prototype" below.

## Machine and runtime
- Mac: Apple M3 Pro (6 performance and 6 efficiency cores, 18-core GPU, 36 GB unified memory), macOS 27.2.
- Runtime: llama-cpp-python 0.3.36 (vendors llama.cpp 0c1e57098, libggml 0.25.3), Python 3.12.14, PyPI sdist.
  Two builds under `$DEVCACHE/venvs/`: `m10-t01-metal` (the sdist default on Apple: Metal plus BLAS, built in 88 s)
  and `m10-t01-cpu` (Metal, BLAS and Accelerate off; the sdist forces Metal on Apple, so it was built from an unpacked
  copy with that forcing removed: its `llama_cpp/lib` holds no libggml-metal or libggml-blas, and every CPU metrics
  file records `gpu_offload: false`). The CPU build stands in for Windows and Linux laptops: plain NEON/dotprod
  kernels with the CPU weight repacking llama.cpp also does on x86, 6 threads.
- PyPI ships llama-cpp-python as an sdist only (0.3.30 to 0.3.37 checked): `pip install` compiles llama.cpp, which
  needs CMake and a C and C++ compiler on the user's machine (MSVC build tools on Windows). 0.3.37 appeared after the
  pin; not measured.
- The product's own modules drive the prototype (`src/auditex/answer_digest.py`, `answer_checks.py`,
  `answer_frames.json`, imported from the main checkout; requests and msal installed into the measurement venvs).

## Models (all Apache-2.0; checked on the publishers' hubs 15 Nov 2026)
| key | family | model | repo @ revision | file | bytes | sha256 |
|---|---|---|---|---|---|---|
| qwen9b | Qwen (default) | Qwen3.5-9B instruct (9.65B, hybrid Gated DeltaNet and attention) | unsloth/Qwen3.5-9B-GGUF @ 3885219b6810b007914f3a7950a8d1b469d598a5 | Qwen3.5-9B-Q4_K_M.gguf | 5,680,522,464 | 03b74727a860a56338e042c4420bb3f04b2fec5734175f4cb9fa853daf52b7e8 |
| mistral8b | Mistral | Ministral 3 8B Instruct 2512 | mistralai/Ministral-3-8B-Instruct-2512-GGUF @ 0102285ad796bd99af90f58de616092e5630e970 | Ministral-3-8B-Instruct-2512-Q4_K_M.gguf | 5,198,911,904 | 33e7a72cf5e6e2cfc2f2847075acc013d68bba023e35310cef86b5cf8fdca761 |
| gemmae4b | Gemma | Gemma 4 E4B it, QAT (8.0B total, 4B effective) | google/gemma-4-E4B-it-qat-q4_0-gguf @ 4b4a2c1d584be7264f87aac328a1bc739ce81b6c | gemma-4-E4B_q4_0-it.gguf | 5,154,941,280 | 676c35070db6dbe52f93e9c864ee0fba4eddea94b9c875d9cb10daff453fbaee |
| qwen4b | Qwen (8 GB laptops) | Qwen3.5-4B instruct (4.66B) | unsloth/Qwen3.5-4B-GGUF @ e87f176479d0855a907a41277aca2f8ee7a09523 | Qwen3.5-4B-Q4_K_M.gguf | 2,740,937,888 | 00fe7986ff5f6b463e62455821146049db6f9313603938a70800d1fb69ef11a4 |

Newest releases checked: Qwen's newest small dense instruct models are Qwen3.5 (Qwen3.6 and Qwen3.8 ship only 27B
and larger); Mistral has nothing newer than Ministral 3 at about 8B (Shieldstral 1.0 3B is a safety classifier);
Gemma 4 offers E2B, E4B, 12B, 26B-A4B and 31B, and E4B is the one of about 8B parameters (12B QAT, 6.98 GB, is the
step up). Qwen publishes no GGUF of Qwen3.5-9B and ggml-org only the 4B, so both Qwen files come from one quantiser
(unsloth); the Mistral and Google files are the publishers' own. Files live under
`/Volumes/4TB/models/auditex-local/<repo>/<revision>/<file>` (clean-development MODELS_ROOT; the brief's
`/Volumes/4TB/dev/models` does not exist on this host), each verified against its sha256 (`scripts/fetch-models.sh`).

## Prototype (DEC-119), `proto/sel_*.py`
- `sel_data.py`: the ten kit qa runs (pseudonymised lab-1 to lab-4, synthetic syn-1 to syn-6) turned into assessment
  rows and passed to `answer_digest.digest_from_assessment`; the live lab run `dummy-tenant-m08e3` read with
  `answer_digest.build_digest` (read only). Each item's rule verdict is also read straight from the source run for the
  independent contradiction count.
- `sel_prompt.py`: a cached system prompt (task, the product's data and sentence notices, how to choose per verdict),
  then per item the product's value and bank lines; a run prompt for the summary (run frames plus the items it may
  highlight). The lean variant moves the fixed frame texts into the cached system prompt, lists frame ids only per
  item and cuts catalogue sentences to their first 12 words (Auditex still renders the full text).
- Decoding: per item a llama.cpp grammar built from `answer_checks.answer_form(item)["schema"]` (the binding's
  json-schema converter), per run one from `summary_form(digest)`; greedy. "compact" removes the converter's optional
  white space between JSON tokens.
- `sel_parallel.py` (batch engine): one llama.cpp context with several sequences, the system prefix decoded once
  and copied into each slot, continuous batching, one grammar per sequence, greedy with an exact top-64 grammar
  check before the full vocabulary. Its answers are identical to the binding's `create_completion` on the same items
  (checked on 8 items, one at a time and four at once).
- Judging: `answer_checks.check_answer` / `check_summary` (pass means no fallback), `answer_item` /
  `answer_summary` for the shown text; `sel_contra.py` counts verdict contradictions independently (hand-written
  wording cues against the source verdict, remediation steps on an item that is not not met, highlighted items and
  counts in the summary against the source).
- Workloads: `t64` = the first 64 items of lab-4 in rule order (52 not met, 12 met; the not met items have the
  longest banks, so this is the slow case) plus its run summary; `runs` = every kit run and the live lab run, each
  sampled evenly per verdict (up to 8 not met, 5 met, 3 not assessed, 3 not applicable) plus each run's summary.
- Each measurement is its own process under `/usr/bin/time -l` (peak resident set size and peak memory footprint);
  n_ctx 4096 (plus 1200 per parallel slot), n_batch 512, 6 threads.

## How the runs went
- Host slots: both hostload slots were held by long jobs (prio-wgex-rc6-rehearsal from 21:49Z, M05-T10-gate) with
  up to eight waiters. The matrix waited 7200 s for a slot, was deferred twice (exit 75) and then ran directly as the
  brief allows (03:17Z to 04:40Z), one model after another; the follow-up likewise (04:40Z to 05:28Z). A VM, a
  simulator and an Xcode build shared the host; each row records the load average at start and end. Ministral's CPU
  run and Gemma's first Metal runs met load averages near 90, so those times are pessimistic (Gemma's Metal t64
  repeated at load 6: 105 s against 112 s).
- Sets: `metal-t64` and `metal-runs` = batch engine, 4 items at once, compact grammar; `u` = the same with the
  uniqueness guard; `metal-t64s` = one item at a time; `metal-t64b` = the binding's plain `create_completion` with the
  converter's white space (the baseline); `l` = lean prompt; `cpu-*` = CPU-only build, 4 at once, answering capped at
  600 s and projected beyond (a projection leaves out the run summary, about 3 per cent of the time).
- Earlier attempt lost: the first `qwen9b metal-runs` crashed (segfault) on lab-3, a run with nothing not met (see
  M10-T03 notes, item 2); it was rerun in the follow-up after the fix.

## Results
Raw outputs and metrics: `/Volumes/4TB/dev/jobs/auditex/M10-T01/sel/<model>/<set>/` (outside the repository; the
live run's rendered answers stay there). Tables from `proto/sel_report.py`.

| model | set | load s | answer s (64 items + summary) | item s (answer s / items) | tokens per item (prompt / generated) | peak RSS MB | peak footprint MB | answers | pass | contradictions (model / shown) | failures | load avg start-end |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| qwen9b | metal-t64 | 50.55 | 170.26 | 2.51 | 373.2 / 37.5 | 7434 | 2321 | 65 | 65 (100.0 %) | 0 / 0 | none | 3.8-7.0 |
| qwen9b | metal-t64u | 7.24 | 170.14 | 2.50 | 373.2 / 37.5 | 7041 | 2279 | 65 | 65 (100.0 %) | 0 / 0 | none | 11.7-4.7 |
| qwen9b | metal-t64s | 6.78 | 216.85 | 3.24 | 373.2 / 37.7 | 7408 | 2123 | 65 | 64 (98.5 %) | 0 / 0 | duplicate 1 | 19.7-11.5 |
| qwen9b | metal-t64b | 0.6 | 297.22 | 4.49 | 373.2 / 52.6 | 7435 | 2085 | 65 | 65 (100.0 %) | 0 / 0 | none | 11.5-2.5 |
| qwen9b | metal-t64l | 0.55 | 138.17 | 2.01 | 248.2 / 37.4 | 7942 | 2568 | 65 | 64 (98.5 %) | 0 / 0 | duplicate 1 | 2.5-4.5 |
| qwen9b | metal-t64lu | 0.68 | 139.57 | 2.04 | 248.2 / 37.3 | 7081 | 2452 | 65 | 65 (100.0 %) | 0 / 0 | none | 5.2-4.5 |
| qwen9b | metal-runs | 0.67 | 480 (181 items, 11 summaries) | 2.21 | 307.2 / 32.6 | 7564 | 2357 | 192 | 167 (87.0 %) | 0 / 0 | duplicate 25 | 4.5-6.3 |
| qwen9b | metal-runsu | 0.85 | 468 (181 items, 11 summaries) | 2.18 | 307.2 / 32.4 | 7579 | 2347 | 192 | 192 (100.0 %) | 0 / 0 | none | 5.1-5.2 |
| qwen9b | cpu-t64 | 2.71 | 766.6 projected (cap 600 s, 51 items) | 11.98 | 406.0 / 40.1 | 11023 | 6659 | 51 | 51 (100.0 %) | 0 / 0 | none | 5.9-19.7 |
| qwen9b | cpu-t64l | 3.17 | 492.54 | 6.87 | 248.2 / 37.5 | 11299 | 7580 | 65 | 64 (98.5 %) | 0 / 0 | duplicate 1 | 4.5-14.5 |
| mistral8b | metal-t64 | 6.57 | 175.35 | 2.58 | 369.5 / 41.4 | 7055 | 2337 | 65 | 65 (100.0 %) | 0 / 0 | none | 14.1-6.1 |
| mistral8b | metal-t64u | 6.35 | 175.81 | 2.58 | 369.5 / 41.4 | 6992 | 2248 | 65 | 65 (100.0 %) | 0 / 0 | none | 3.7-5.6 |
| mistral8b | metal-runs | 0.75 | 466 (181 items, 11 summaries) | 2.14 | 302.7 / 36.0 | 7258 | 2349 | 192 | 192 (100.0 %) | 0 / 0 | none | 6.1-12.1 |
| mistral8b | metal-runsu | 0.68 | 496 (181 items, 11 summaries) | 2.29 | 302.7 / 36.0 | 7150 | 2316 | 192 | 192 (100.0 %) | 0 / 0 | none | 5.6-6.0 |
| mistral8b | cpu-t64 | 2.84 | 918.3 projected (cap 600 s, 44 items) | 14.35 | 403.1 / 44.0 | 11102 | 7065 | 44 | 44 (100.0 %) | 0 / 0 | none | 12.1-93.0 |
| gemmae4b | metal-t64 | 8.4 | 111.63 | 1.65 | 373.4 / 37.2 | 7148 | 2573 | 65 | 65 (100.0 %) | 0 / 0 | none | 93.0-96.0 |
| gemmae4b | metal-t64u | 64.33 | 105.24 | 1.56 | 373.4 / 37.2 | 7172 | 2592 | 65 | 65 (100.0 %) | 0 / 0 | none | 6.0-4.8 |
| gemmae4b | metal-runs | 0.83 | 295 (181 items, 11 summaries) | 1.37 | 305.5 / 32.1 | 7349 | 2595 | 192 | 192 (100.0 %) | 0 / 0 | none | 88.5-7.0 |
| gemmae4b | metal-runsu | 0.81 | 297 (181 items, 11 summaries) | 1.38 | 305.5 / 32.1 | 7317 | 2589 | 192 | 192 (100.0 %) | 0 / 0 | none | 4.6-8.4 |
| gemmae4b | cpu-t64 | 1.59 | 341.03 | 4.97 | 373.4 / 37.5 | 8972 | 5176 | 65 | 65 (100.0 %) | 0 / 0 | none | 7.0-15.3 |
| qwen4b | metal-t64 | 3.25 | 100.62 | 1.48 | 373.2 / 37.3 | 4728 | 2384 | 65 | 65 (100.0 %) | 0 / 0 | none | 14.5-9.4 |
| qwen4b | metal-t64u | 12.24 | 97.37 | 1.44 | 373.2 / 37.3 | 4773 | 2336 | 65 | 65 (100.0 %) | 0 / 0 | none | 6.3-4.1 |
| qwen4b | metal-runs | 0.53 | 267 (181 items, 11 summaries) | 1.21 | 307.2 / 30.2 | 4966 | 2394 | 192 | 192 (100.0 %) | 0 / 0 | none | 9.5-7.6 |
| qwen4b | metal-runsu | 0.52 | 265 (181 items, 11 summaries) | 1.23 | 307.2 / 30.2 | 4897 | 2356 | 192 | 192 (100.0 %) | 0 / 0 | none | 4.1-3.7 |
| qwen4b | cpu-t64 | 1.51 | 403.22 | 5.82 | 373.2 / 37.5 | 7185 | 5104 | 65 | 65 (100.0 %) | 0 / 0 | none | 7.6-14.1 |

| model | source | answers | pass | contradictions (model / shown) |
|---|---|---|---|---|
| qwen9b metal-runs | lab | 55 | 45 (81.8 %) | 0 / 0 |
| qwen9b metal-runs | live-lab | 17 | 14 (82.4 %) | 0 / 0 |
| qwen9b metal-runs | synthetic | 120 | 108 (90.0 %) | 0 / 0 |
| qwen9b metal-runsu | lab | 55 | 55 (100.0 %) | 0 / 0 |
| qwen9b metal-runsu | live-lab | 17 | 17 (100.0 %) | 0 / 0 |
| qwen9b metal-runsu | synthetic | 120 | 120 (100.0 %) | 0 / 0 |
| mistral8b metal-runs | lab | 55 | 55 (100.0 %) | 0 / 0 |
| mistral8b metal-runs | live-lab | 17 | 17 (100.0 %) | 0 / 0 |
| mistral8b metal-runs | synthetic | 120 | 120 (100.0 %) | 0 / 0 |
| mistral8b metal-runsu | lab | 55 | 55 (100.0 %) | 0 / 0 |
| mistral8b metal-runsu | live-lab | 17 | 17 (100.0 %) | 0 / 0 |
| mistral8b metal-runsu | synthetic | 120 | 120 (100.0 %) | 0 / 0 |
| gemmae4b metal-runs | lab | 55 | 55 (100.0 %) | 0 / 0 |
| gemmae4b metal-runs | live-lab | 17 | 17 (100.0 %) | 0 / 0 |
| gemmae4b metal-runs | synthetic | 120 | 120 (100.0 %) | 0 / 0 |
| gemmae4b metal-runsu | lab | 55 | 55 (100.0 %) | 0 / 0 |
| gemmae4b metal-runsu | live-lab | 17 | 17 (100.0 %) | 0 / 0 |
| gemmae4b metal-runsu | synthetic | 120 | 120 (100.0 %) | 0 / 0 |
| qwen4b metal-runs | lab | 55 | 55 (100.0 %) | 0 / 0 |
| qwen4b metal-runs | live-lab | 17 | 17 (100.0 %) | 0 / 0 |
| qwen4b metal-runs | synthetic | 120 | 120 (100.0 %) | 0 / 0 |
| qwen4b metal-runsu | lab | 55 | 55 (100.0 %) | 0 / 0 |
| qwen4b metal-runsu | live-lab | 17 | 17 (100.0 %) | 0 / 0 |
| qwen4b metal-runsu | synthetic | 120 | 120 (100.0 %) | 0 / 0 |

| model | set | opens with verdict | mean sentences | not met items given steps | summary highlights SHALL |
|---|---|---|---|---|---|
| qwen9b | metal-t64 | 100 % | 6.81 | 100 % | 5/5 |
| qwen9b | metal-t64u | 100 % | 6.81 | 100 % | 5/5 |
| qwen9b | metal-t64s | 100 % | 6.83 | 100 % | 5/5 |
| qwen9b | metal-t64b | 100 % | 6.78 | 100 % | 5/5 |
| qwen9b | metal-t64l | 100 % | 7.0 | 100 % | 5/5 |
| qwen9b | metal-t64lu | 100 % | 7.0 | 100 % | 5/5 |
| qwen9b | metal-runs | 100 % | 5.59 | 100 % | 50/50 |
| qwen9b | metal-runsu | 100 % | 5.59 | 100 % | 50/50 |
| qwen9b | cpu-t64 | 100 % | 7.53 | 100 % |  |
| qwen9b | cpu-t64l | 100 % | 6.98 | 100 % | 5/5 |
| mistral8b | metal-t64 | 100 % | 7.06 | 88 % | 5/5 |
| mistral8b | metal-t64u | 100 % | 7.06 | 88 % | 5/5 |
| mistral8b | metal-runs | 100 % | 5.7 | 99 % | 49/50 |
| mistral8b | metal-runsu | 100 % | 5.7 | 99 % | 49/50 |
| mistral8b | cpu-t64 | 100 % | 7.7 | 93 % |  |
| gemmae4b | metal-t64 | 100 % | 6.36 | 100 % | 0/0 |
| gemmae4b | metal-t64u | 100 % | 6.36 | 100 % | 0/0 |
| gemmae4b | metal-runs | 100 % | 5.09 | 100 % | 0/0 |
| gemmae4b | metal-runsu | 100 % | 5.09 | 100 % | 0/0 |
| gemmae4b | cpu-t64 | 100 % | 6.38 | 100 % | 0/0 |
| qwen4b | metal-t64 | 100 % | 6.72 | 100 % | 5/5 |
| qwen4b | metal-t64u | 100 % | 6.72 | 100 % | 5/5 |
| qwen4b | metal-runs | 100 % | 5.29 | 100 % | 49/50 |
| qwen4b | metal-runsu | 100 % | 5.29 | 100 % | 49/50 |
| qwen4b | cpu-t64 | 100 % | 6.7 | 100 % | 5/5 |

## Findings
- Pass rate: under the schema grammar every answer parses and no id can be unknown, out of the bank or past a limit.
  The one failure the grammar admits is a repeated id: llama.cpp's json-schema converter ignores `uniqueItems`.
  Qwen3.5-9B pads `use` to eight ids by repeating one when the bank runs short: 87.0 per cent on the runs without a
  guard (25 duplicates in 192 answers), 98.5 per cent on three t64 sets. With the uniqueness guard
  (`proto/sel_unique.py` in `sel_parallel.GrammarPick`: a candidate token is refused when the list would repeat an id
  or its unfinished id can only complete into a listed one; the next best admitted token is taken) every model passes
  100 per cent: 65 of 65 on t64 and 192 of 192 on the runs (55 lab, 17 live lab, 120 synthetic) for each model.
  Ministral, Gemma and Qwen3.5-4B produced no duplicates even without the guard.
- Contradictions: 0 in every set, counted independently of the product checks (`proto/sel_contra.py`: wording cues
  against the source verdict, remediation steps on an item that is not not met, highlighted items and counts against
  the source).
- Memory (64-check run; peak RSS counts the mapped model file, footprint the process's own memory): Metal 4.7 to
  7.9 GB RSS, 2.1 to 2.6 GB footprint for every model; CPU-only 11.0 to 11.3 GB RSS and 6.7 to 7.6 GB footprint for
  the 8B-class models (the CPU backend repacks the weights into its own buffers, so the mapped file pages count twice
  in RSS and are reclaimable after load), 9.0 GB RSS and 5.2 GB footprint for Gemma E4B, 7.2 GB RSS and 5.1 GB
  footprint for Qwen3.5-4B. Every 8B-class model stays under 16 GB and the 4B under 8 GB even counted by RSS.
- Load: 0.5 to 8 s warm; 50 to 64 s cold from the external SSD for a 5 GB file (a laptop's internal disk is faster).
- Time to answer a 64-check run (64 items plus the run summary, guard on, 4 at once): Metal Qwen3.5-9B 170 s,
  Ministral 176 s, Gemma E4B 105 s, Qwen3.5-4B 97 s; with the lean prompt Qwen3.5-9B 140 s. CPU-only (6 threads):
  Qwen3.5-9B 767 s projected (lean 493 s), Ministral 918 s projected (host load near 90), Gemma E4B 341 s,
  Qwen3.5-4B 403 s. The baseline binding path (one at a time, the converter's white space) takes 297 s for
  Qwen3.5-9B on Metal; compact JSON cuts generated tokens from 52.6 to 37.5 per item and 4 at once cuts 217 s to
  170 s. Per item the prompt (about 370 tokens of values and bank text, 250 lean) costs more than the answer (about
  37 tokens), which is why batching helps less than it would for long answers.
- Choosing (what the model adds; for M10-T04's usefulness judgement): every model opens with the verdict sentence
  (100 per cent) and gives remediation steps on not met items (Qwen and Gemma 100 per cent, Ministral 88 to 99).
  Run summaries: Qwen3.5-9B highlights SHALL items first (50 of 50 highlights), Ministral and Qwen3.5-4B 49 of 50;
  Gemma E4B never highlights an item (0 highlights in every summary; still a passing answer, as an empty list is
  allowed).

## What the prompt needed
- Form: nothing. The grammar from `answer_form` and `summary_form` makes the form right by construction; the prose
  prototype needed a ban list and two repair rounds for the same models.
- Pass rate: the uniqueness guard, not the prompt. "Each id once" in the prompt did not stop Qwen3.5-9B's repeats.
- Choice: the per-verdict guidance in the system prompt (open with the verdict sentence, then for not met the SHALL
  frame, change-needed, requirement, reason, steps; for met the requirement and no-change-needed) and, for the
  summary, "SHALL before SHOULD, then sign-in, administrators, legacy access". Gemma ignores the highlight guidance.
- Quoted data: the product's data and sentence notices sit in the cached system prompt; values and sentences reach
  the model only as quoted lines (`answer_digest.quoted`).
- Prompt files: `proto/sel_prompt.py`; the rendered prompts per model are in each output folder
  (`prompt-item.txt`, `prompt-summary.txt`).

## Notes for M10-T03 (runner)
1. Enforce `uniqueItems` while decoding (the converter drops it); without it Qwen3.5-9B misses the 99 per cent bar.
2. An empty enum (a run with nothing not met gives `highlight` an empty enum; an item without showable values would
   do the same for `show`) makes the converter emit an empty rule that llama.cpp rejects; through the binding the
   NULL sampler then segfaults the process. Drop the empty rule (the list rule is already `[]`) or build the schema
   without `items`, and check the sampler is not NULL.
3. Use the compact grammar (no optional white space) and answer about 4 items at once (one context, a sequence per
   item, the system prefix decoded once and copied with `llama_memory_seq_cp`; a finished recurrent sequence is
   removed whole and copied again). `proto/sel_parallel.py` gives answers identical to `create_completion`.
4. Grammar sampling over the whole vocabulary is cheap (0.01 ms per token); the time that looks like sampling is the
   logits read waiting for the GPU. A top-64 grammar check before the full vocabulary is exact for greedy decoding.
5. `LlamaModel.token_to_piece` in llama-cpp-python 0.3.36 returns its whole 32-byte buffer (NUL padded); strip it.
6. PyPI has llama-cpp-python as an sdist only (0.3.30 to 0.3.37): `pip install auditex[local]` compiles llama.cpp and
   needs CMake and a C and C++ compiler (MSVC on Windows); the Metal build took 88 s here. Decide the wheel source.
7. The lean prompt (frame texts once in the system prompt, catalogue sentences cut to 12 words) saves 18 per cent on
   Metal and 36 per cent on CPU with the same pass rate; consider it, or skipping the model for not assessed and not
   applicable items, to approach the 3-minute bar on CPU-only laptops.

## Prose prototype (superseded by DEC-119)
The first prototype had the model write one sentence per item with value references, checked by a port of the AIRR
kit's answer form. On Qwen3.5-4B t64: prompt v1 23 per cent, v2 55, v3 with a token ban list 89, v4 with the ban
list and two repair rounds 100 (92 on the first pass), 0 contradictions; on all runs 99.85 per cent. REV-M10-T02
then showed that free composition can still assert tenant state, which DEC-119 replaced with selection.
