## RESULT INV4-bases
status: done
summary: Apache-2.0 LoRA bases in 8-70B: Ministral 3 8B/14B, Gemma 4 12B/26B-MoE/31B, Qwen3.8-27B. Qwen 4 is not released (no repo on the Qwen HF org). Isambard docs do not state compute-node internet access or PEFT/transformers/bitsandbytes pins. Confidence medium: licences and sizes are from model cards and vendor pages; llama.cpp support and Isambard networking are unresolved.
changes: none (Write tool disabled; evidence held in this reply)
verification: 8 of 10 searches (7 WebSearch, 1 Exa web_search_exa, run before any WebSearch on the Isambard PEFT question, against the brief's order); 24 page fetches (13 URLs via Exa fetch, 11 WebFetch); no code run
risks: 1) Qwen3.8-27B release date is not on its card; the org page only shows "updated 4 days ago". 2) llama.cpp GGUF support for Qwen3.8 and Mistral Small 4 is not confirmed on a primary source. 3) Isambard compute-node internet access is unknown; confirm with support before planning fetches on nodes.
questions_for_g: none
### Findings
Direct answer:
- In range, Apache 2.0: Ministral 3 8B and 14B (Dec 2025); Gemma 4 12B, 26B A4B, 31B (Apr 2026); Qwen3.8-27B (Nov 2026, dense).
- Mistral Small 4 (119B MoE) is Apache 2.0 but above the 8-70B range.
- Qwen 4: not released; no repo on the Qwen HF org.
- Llama: last Llama is 4 (Apr 2025, custom licence); Meta's newer open weights are Muse, not Llama.
- Isambard: compute-node internet and package version pins are not stated in the docs.
1. Ministral 3 (3B/8B/14B, base/instruct/reasoning, vision), released 2 Dec 2025, Apache 2.0. https://mistral.ai/news/mistral-3 "All models are released under the Apache 2.0 license." Context 256k per https://huggingface.co/mistralai/Ministral-3-8B-Instruct-2512 "Supports a 256k context window." Official GGUF repo exists: https://huggingface.co/mistralai/Ministral-3-8B-Instruct-2512-GGUF "How to use ... with llama.cpp:"
2. Gemma 4: Apache 2.0; five sizes (E2B, E4B, 12B, 26B A4B, 31B); 256K medium, 128K small. https://ai.google.dev/gemma/docs/core/model_card_4 "License: Apache 2.0". Release 2 Apr 2026 (secondary: https://www.techwyse.com/news/ai-search/google-deepmind-gemma-4-open-models-apache-2-0-release). Conflict: launch blog lists four sizes without 12B; the model card is more authoritative. llama.cpp: Gemma 4 FP8 change in b12274, https://github.com/ggml-org/llama.cpp/releases "Enable Gemma 4 Assistant with FP8 by storing and fetching scale ptrs".
3. Qwen3.8-27B: dense 28B vision-language model; HF licence field apache-2.0; https://huggingface.co/Qwen/Qwen3.8-27B "Context Length: 262,144 natively and extensible up to 1,000,000 tokens." Card says it runs in "llama.cpp, Ollama, LM Studio". Conflict: one secondary source names a "Qwen Community License 1.0" for Flash-Next (unverified); the 27B card field governs.
4. Qwen3.8-2.4T-A95B: licence field "qwen3.8-max", not Apache; 2.4T total, out of range. https://huggingface.co/Qwen/Qwen3.8-2.4T-A95B
5. Qwen 4: the Qwen org lists only Qwen3.8 repos (https://huggingface.co/Qwen). Sizes, licence and date: none found. Secondary (unverified) reports say it is "in training".
6. Mistral Small 4: 119B total, 6.5B active, 256k context, released 16 Mar 2026. https://docs.mistral.ai/models/mistral-small-4-0-26-03.md "Licenses: Apache 2.0". Weights about 242 GB (https://simonwillison.net/2026/Mar/16/mistral-small-4/ "The new model is 242GB on Hugging Face.").
7. Mistral Large 4: 1T total, about 52B active, 1M context. Licence is the Mistral Ecosystem Open-Weight License (modified MIT). https://huggingface.co/mistralai/Mistral-Large-4-1T-A52B/blob/main/LICENSE "must enter into a separate commercial license with Mistral" applies only to Model-as-a-Service. Derivatives allowed with attribution notice. Out of range.
8. Llama: Llama 4 Community License (custom, "Built with Llama", 700M MAU clause); secondary only: https://callsphere.ai/blog/td30-gmm-healthcare-llama-4-licensing-commercial-use. Muse Glimmer 30B reported Apache 2.0 (secondary, date unverified): https://mer.vin/news/muse-glimmer-30b-is-metas-first-open-weight-model-since-llama-4/
9. Phi-4 (14B): MIT per secondary https://the-decoder.com/microsoft-releases-full-phi-4-model-with-weights-under-mit-license/. 2026 Phi claims found only on aggregators; unverified.
10. Isambard-AI: nodes are aarch64, 4 x GH200 each; https://docs.isambard.ac.uk/specs/ "code needs to be compiled for aarch64". Compute-node internet: not stated in https://docs.isambard.ac.uk/user-documentation/faqs/ or the ML-packages page. The HF page's "rate limits unauthenticated API traffic per IP address" is not proof of outbound access (inference).
11. Isambard package versions: no PEFT, transformers or bitsandbytes pins in https://docs.isambard.ac.uk/user-documentation/applications/ML-packages/ ("prefer more recent releases of machine learning packages"). Login nodes have no GPUs; install on compute nodes via srun.
12. bitsandbytes: aarch64 wheels target sm75/sm80/sm90 (GH200 is sm90, inference); requires "PyTorch >= 2.4" and Python >= 3.10 (https://huggingface.co/docs/bitsandbytes/en/installation). No GH200 version report found.
13. Secondary: https://github.com/GeodesicResearch/isambard-onboarding-sample says plain pip torch on aarch64 pulls CUDA-13 wheels that fail on the CUDA-12 driver; `--torch-backend=auto` fixes it. Undated.
Open points:
- Medium 3.5 (on the Mistral HF org) not checked for size or licence.
- Qwen 4 status and licence: re-check the Qwen HF org before January.
- Isambard: outbound internet and version pins need a support query or a GH200 user report.
- Muse Glimmer licence and date: secondary only.
- Qwen3.8-27B llama.cpp GGUF build: not confirmed on a primary source.
