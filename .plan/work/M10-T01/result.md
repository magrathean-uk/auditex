## RESULT M10-T01
status: done
summary: Runtime and models chosen by measurement on this Mac for the DEC-119 answer (the model selects ids; prototype drives the product's answer_digest and answer_checks, decoding constrained by llama.cpp grammars from answer_form and summary_form). With a uniqueness guard every model passes 100 per cent (65 t64 answers plus 192 lab, live-lab and synthetic answers each) with 0 contradictions; without it Qwen3.5-9B falls to 87 per cent (repeated ids). All fit 16 GB, the 4B fits 8 GB. Metal answers a 64-check run in 97 to 176 s, CPU-only in 341 to 918 s. Hostload slots stayed busy: the matrix and follow-up ran directly after two deferrals each.
changes: .plan/work/M10-T01/ only (measurements.md, progress.md, result.md, proto/sel_*.py, scripts/sel-*.sh); no product files, no commits
verification: grep -qx 'models: chosen' .plan/work/M10-T01/result.md && test -s .plan/work/M10-T01/measurements.md: pass; git status shows no product change: pass
risks: CPU-only laptops miss the 3-minute bar with 8B models (Qwen3.5-9B 767 s, 493 s with the lean prompt; CPU rows ran under shared host load up to 90), so M10-T04 needs the lean prompt or fewer model calls; PyPI has llama-cpp-python as an sdist only, so the optional extra compiles llama.cpp unless M10-T03 picks a wheel source; Gemma E4B never highlights items in the run summary
questions_for_g: none
### Findings
models: chosen
runtime: llama-cpp-python 0.3.36
model: qwen unsloth/Qwen3.5-9B-GGUF 3885219b6810b007914f3a7950a8d1b469d598a5 Qwen3.5-9B-Q4_K_M.gguf 03b74727a860a56338e042c4420bb3f04b2fec5734175f4cb9fa853daf52b7e8
model: mistral mistralai/Ministral-3-8B-Instruct-2512-GGUF 0102285ad796bd99af90f58de616092e5630e970 Ministral-3-8B-Instruct-2512-Q4_K_M.gguf 33e7a72cf5e6e2cfc2f2847075acc013d68bba023e35310cef86b5cf8fdca761
model: gemma google/gemma-4-E4B-it-qat-q4_0-gguf 4b4a2c1d584be7264f87aac328a1bc739ce81b6c gemma-4-E4B_q4_0-it.gguf 676c35070db6dbe52f93e9c864ee0fba4eddea94b9c875d9cb10daff453fbaee
model: small unsloth/Qwen3.5-4B-GGUF e87f176479d0855a907a41277aca2f8ee7a09523 Qwen3.5-4B-Q4_K_M.gguf 00fe7986ff5f6b463e62455821146049db6f9313603938a70800d1fb69ef11a4
laptop-4b: pass
- All Apache-2.0; files 5.68, 5.20, 5.15 and 2.74 GB, each verified by sha256 under the external model store.
- 64-check run, Metal, 4 at once (load warm 0.5 to 12 s, cold 50 to 64 s): qwen 170 s, mistral 176 s, gemma 105 s, small 97 s; qwen lean 140 s.
- 64-check run, CPU-only (6 threads): qwen 767 s projected (lean 493 s), mistral 918 s projected, gemma 341 s, small 403 s.
- Peak RSS / footprint: Metal 4.7-7.9 / 2.1-2.6 GB for all; CPU qwen and mistral 11.0-11.3 / 6.7-7.6 GB, gemma 9.0 / 5.2 GB, small 7.2 / 5.1 GB.
- Pass with guard 100 per cent for all, 0 contradictions; without guard qwen 87.0 per cent on runs (25 duplicates of 192), the others 100.
- Prompt: form needs nothing (the grammar); the pass rate needs the uniqueness guard; per-verdict choice guidance gives 100 per cent verdict-first answers.
- M10-T03 must: enforce uniqueItems in decoding; drop the empty grammar rule an empty enum gives (lab-3 crashed llama.cpp); use compact JSON and 4 items at once (297 s baseline to 170 s); details in .plan/work/M10-T01/measurements.md.
recommendation: default qwen (Qwen3.5-9B Q4_K_M), choices mistral (Ministral 3 8B) and gemma (Gemma 4 E4B), small (Qwen3.5-4B) for 8 GB laptops; runtime llama-cpp-python 0.3.36 with grammar decoding, the uniqueness guard and 4 items at once.
