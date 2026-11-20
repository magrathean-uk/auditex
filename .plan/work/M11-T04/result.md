# M11-T04 result: train, quantise and evaluate on three bases

Method: kit trainer (LoRA r16, scale 2.0, `v10` preset) on the M11-T03 data version `101c02cd2c58...` train split, completion header normalised. Merge, then GGUF with llama.cpp `9e9619d030bbe6b584d826a0a6cf06e38251f52b`. Checkpoint and quantisation chosen on the validation split (40 and 150 distinct-prompt sets) by the M10 checks on generated answers, never by eval loss. One held-out run per base on the sealed split (422 distinct prompts, 1,674 weighted rows, 172,422 sentences); the held-out rows stayed on the project store and were read only by those jobs. No tuning after them. Weights and GGUFs stay on the project store.

Why not plain Q4_K_M: it breaks long answers (Qwen step 1405, 40 prompts: 0.49 sentence pass rate at plain Q4_K_M, 1.00 at Q8_0 and at imatrix Q6_K; Qwen imatrix Q4_K_M still 0.98). An imatrix (train-split calibration, seed 42, 24 rows) with Q5_K_M or Q6_K recovers it. Gemma needs per-layer-embedding tensors at q4 (`per_layer_token_embd.weight=q4_k`) to fit: plain imatrix Q6_K peaks at 6.61 GB and Q5_K_M at 6.15 GB, both over the 6 GB cap.

## Per base

| base | pin (repo @ revision, licence) | checkpoint | quant | GGUF sha256 | bytes | peak RSS |
|---|---|---|---|---|---|---|
| Qwen | Qwen/Qwen3.5-4B @ 851bf6e806efd8d0a36b00ddf55e13ccb7b8cd0a, apache-2.0 | step 1405 | imatrix Q6_K | c9540d48d63bcf479bc0a64012b04151f17947560dd241ada61bdb74a8675c56 | 3563028672 | 4.74 GB |
| Mistral | mistralai/Ministral-3-3B-Instruct-2512-BF16 @ b6d637bef2393152b3da2b2fde72eecdee30557e, apache-2.0 | step 1200 | imatrix Q6_K | e74d589b573a8298c90b4e6784651560f18950e0e731859a4331ad10bb0c655f | 2821261216 | 5.87 GB |
| Gemma | google/gemma-4-E4B-it @ 4ecc2ba63bcac23ba4a767fc87025b1450f84c9c, apache-2.0 | step 400 | imatrix Q6_K, per-layer embedding q4_k | b38f6e548031b50e5227b6a439f0c36c3bc3792ae7904e1c5fc156416912d73e | 5490595360 | 5.70 GB |

Peak RSS: llama-server, CPU only, one slot, 32,768 context, f16 KV; all three are within the 6 GB cap, Mistral and Gemma with little margin.

Checkpoint choice on validation (weighted sentence pass rate; contradictions; fallbacks):
- Qwen: step 1405 and step 1200, both imatrix Q6_K at 150 prompts: 0.9999 with 4 and 8 fallbacks, no contradictions. Step 1405 taken. Final step unquantised-style plain Q4_K_M was rejected (above).
- Mistral: step 1200 imatrix Q6_K 0.9929, 0 contradictions; step 1389 imatrix Q6_K 0.9929 with 4 contradiction rows; step 1389 Q8_0 0.9931 but peaks at 6.72 GB (over the cap). Step 1200 taken.
- Gemma: step 400 per-layer q4 Q6_K 0.9968 (40 prompts), final step 499 0.9956, and 499 uses 5.98 GB against 5.70 GB. Step 400 taken.

## Held-out, one run per base (bar: sentence pass >= 0.99, zero fallback, zero contradictions, DEC-120 completeness, DEC-114 injection, zero header problems)

| base | sentence pass | fallback sentences | rows with contradictions | completeness | leaks (injection) | header problems | missing answers | result |
|---|---|---|---|---|---|---|---|---|
| Qwen (step 1405, Q6_K) | 0.99478 | 900 | 20 | 8 | 4 | 64 | 2 | fail |
| Mistral (step 1200, Q6_K) | 0.97576 | 4180 | 12 | 40 | 4 | 100 | 10 | fail |
| Gemma (step 400, Q6_K) | 0.99171 | 1430 | 0 | 8 | 4 | 442 | 2 | fail |

Row counts are weighted rows out of 1,674. Gemma is clean on contradictions but fails on fallbacks, completeness, leaks and above all the answer header line (442 rows).

## Off-the-shelf comparison (M10 `qwen`, same 1,674 rows)

Sentence pass rate 1.0, 0 fallbacks, 0 contradictions, 0 completeness problems, 0 header problems, 10 rows with leak flags (the fine-tuned models flag 4). The off-the-shelf model fails only the injection check; none of the three fine-tuned compact models beats it on this split.

model-bar: fail (no base met the bar)

## GPU hours (DEC-115 cap 5,000)

Recomputed with `m4_gpuhours.py` (gpu seconds / 3600, job ids counted once) from the scheduler exports of M11-T01 (37.27), M11-T02 (34.78 over both attack exports), M11-T03 (41.22) and M11-T04 (95.10, 119 jobs, export `runs/m11t04/usage/accounting-train-eval.psv` on the project store, with SHA256SUMS). Total 208.38.

m11-gpu-hours: 208.38
