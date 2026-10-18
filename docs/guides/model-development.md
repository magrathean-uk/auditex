# Auditex model development

Prepare reviewed knowledge for **one base model and one LoRA adapter**. OpenAdmin
and M365 Expert can supply comparison answers for review; their different model
architectures do not make their weights compatible for merging. Collection,
findings and evidence references remain deterministic Auditex responsibilities.

This workflow assembles review materials and supports local GGUF benchmarks.
Training and JUPITER runtime qualification remain separate steps.

## Available materials

Run `auditex model sources` to inspect the pinned source inventory. The prepared
external materials live under `/Volumes/4TB/models/auditex/`:

- Two downloaded, checksum-verified Q4_K_M GGUF comparison models: OpenAdmin 8B
  and M365 Expert v3, approximately 10.2 GB combined. These are inference
  artifacts, not the BF16 training base or compatible adapter weights.
- OpenAdmin's public SFT release contains **499 unique conversations**, rather
  than the full training corpus behind its released 8B model. Its repository
  also contains overlapping assembled runs and separate evaluation material.
- A matching public corpus for M365 Expert's claimed 40,962 examples was not
  established. Do not represent that corpus as acquired.
- The proposed Qwen base revision is pinned in the source catalogue; its
  training weights and the GH200 runtime still need staging and qualification.

`examples/model_development/` supplies 48 synthetic, **unreviewed** Auditex cases
with 32 train, eight validation and eight test cases in separate families.
Recorded response fixtures test file handling; they are not model outputs or
benchmark results. Proposed expected labels are not approved gold labels.
The synthetic generator supplies the same candidate limitation and
recommendation vocabulary to every case, including irrelevant choices. Earlier
v1 prompts supplied the expected selections directly. The current v3 also asks
direct factual questions where earlier proof/meta-questions ambiguously expected
`unknown`. An explicitly unperformed detection exercise now correctly yields
`confirmed: false` for whether validation occurred; attack occurrence remains
unknown. Case IDs and split families are retained; prompt and target hashes
change. Exported examples remain unreviewed proposals.

## Prepare and inspect locally

From the repository root, select the prepared kit directory. Use new output
paths; commands refuse to replace existing results.

```sh
source ~/dev/env.zsh
export AUDITEX_MODEL_ROOT=/Volumes/4TB/models/auditex
export AUDITEX_KIT=/absolute/path/to/the/prepared/development-kit

clean-development run --session session-only -- .venv/bin/auditex model sources
clean-development run --session session-only -- .venv/bin/auditex model stage \
  --manifest "$AUDITEX_KIT/public-source-manifest.json" \
  --output-dir "$AUDITEX_KIT/staged-public-corpus-new"

clean-development run --session session-only -- .venv/bin/auditex model evaluate \
  --cases examples/model_development/cases.jsonl \
  --responses examples/model_development/fixture-model-a.jsonl \
  --output "$AUDITEX_KIT/review/fixture-evaluation-new.json"

clean-development run --session session-only -- .venv/bin/auditex model combine \
  --cases examples/model_development/cases.jsonl \
  --responses examples/model_development/fixture-model-a.jsonl \
  --responses examples/model_development/fixture-model-b.jsonl \
  --output "$AUDITEX_KIT/review/fixture-combined-new.json"

clean-development run --session session-only -- .venv/bin/auditex model prepare \
  --cases examples/model_development/cases.jsonl \
  --output-dir "$AUDITEX_KIT/training-pack-new" \
  --base-model Qwen/Qwen3.8-27B \
  --revision 1d4bf0f2ff6012fd82039f2fa52739d0dd7c60c0
```

The assembled public stage contains 4,225 unreviewed candidate conversations;
conflicting prompt variants are quarantined. Its 448 source evaluation YAML
files remain separate and opaque; semantic non-overlap has not been established.
Staging does not turn public conversations into reviewed Auditex examples. Preparation exports
approved prompt/completion records to `train.jsonl` and `validation.jsonl`,
keeps `test.jsonl` separate and places unreviewed cases in `quarantine.jsonl`.
The starter pack therefore has `job_ready: false` and no training rows.

## Case and answer contract

Each JSONL case has `id`, `family`, `split`, `provenance`, `messages` and
`expected`. Provenance records `source`, a boolean `synthetic`,
`review_status` (`unreviewed` or `approved`) and a `reviewer` required for approved
cases (optional for unreviewed proposals).
Messages contain string `role`/`content` fields and finish with an assistant
response. Approval describes an actual review; scripts never grant it.

Expected answers contain `claims`, `limitations`, `recommendations` and the
case-local `allowed_evidence_ids`. Each claim has an `id`, a status of
`confirmed`, `inferred` or `unknown`, `evidence_ids`, and an optional typed
JSON `value`. Limitations and recommendations are stable IDs, not free prose.
Recorded answer rows are `{case_id, model_id, response}`; `response` contains
the same three answer fields without the evidence allowlist.

The loader rejects duplicate IDs, family or normalized-prompt leakage across
splits, conflicting prompt labels and approved answers that disagree with their
rubric. Evaluation checks exact claim status, typed values, evidence sets and
gap/recommendation IDs. It does not prove prose entailment or source truth.
Combination requires every supplied model to pass the reviewed rubric; voting
does not establish truth. Only approved **train** cases become candidates.
Export reviewed `training_candidates` as cases JSONL and supply independently
reviewed validation/test cases in separate files using repeated `--cases`.
Public staging records and recorded-response JSONL are not training-case inputs.

## Cases from a directory lab

After collecting a finalized audit of explicitly prefixed synthetic directory
fixtures, export configuration-reasoning proposals locally:

```sh
clean-development run --session session-only -- .venv/bin/python scripts/build-lab-model-cases.py \
  --run-dir /absolute/path/to/finalized-lab-audit \
  --fixture-prefix auditex-lab-example \
  --output-dir /absolute/path/to/new-lab-cases
```

The exporter revalidates the bundle, selects only matching user, group and
application records, and copies a small configuration-field allowlist. It omits
principal names, tenant domains, object GUIDs and timestamps from case content;
fixture label suffixes remain untrusted evidence text. Provenance records source
artifact hashes and record pointers. Missing fields produce unknown targets.
Tenant grouping uses the observed organization UUID when the run manifest lacks
one, and rejects conflicting identities.
Exports cover the matching normalized records only. Paged collectors retain a
20-row inline sample, but current normalization reads all collected chunk rows.
Check `normalization_complete`, endpoint coverage and collection/fan-out limits
before assuming all fixtures appear. Older runs may still contain sample-only
normalization. A valid bundle alone does not establish complete collection.

These are live observations of synthetic fixtures, with unreviewed proposed
answers. Every exported case stays in one tenant-specific **train** family,
including later runs from that tenant. Build independent validation/test
scenarios separately. Exporting cases neither approves targets nor runs a model.

## Local GGUF benchmarks

`scripts/run-model-benchmark.py` launches one owned localhost `llama-server`,
runs explicitly reviewed cases sequentially, and stops only that subprocess.
Supply an existing native runtime, a local GGUF, a model hash and a new output
directory:

```sh
clean-development run --session session-only -- .venv/bin/python scripts/run-model-benchmark.py \
  --server /absolute/path/to/llama-server --check-runtime
clean-development run --session session-only -- .venv/bin/python scripts/run-model-benchmark.py \
  --server /absolute/path/to/llama-server --model /absolute/path/to/model.gguf \
  --model-id reviewed-model-label --model-sha256 EXPECTED_SHA256 \
  --cases /absolute/path/to/reviewed-cases.jsonl --output-dir /absolute/path/to/new-results \
  --response-format json-object --disable-thinking --ctx-size 8192 \
  --max-tokens 2048 --threads 6 --gpu-layers 99 --seed 42
```

Only `messages[:-1]` enters inference. The final assistant target and expected
rubric stay evaluation-only. The manifest records model/runtime hashes, the
embedded template, exact protocol settings, prompt fingerprints and usage.
Generic JSON-object constraints and thinking settings are explicit. Malformed,
truncated or failed responses retain raw traces; no response repair is performed.
Case approval is attributed provenance, not proof of independent human review.
Report agent-reviewed reference results as such, and separate same-tenant live
calibration from held-out synthetic results. Exact ID matching is a mechanical
protocol check, not a standalone measure of natural-language factual accuracy.

## Claude execution handoff

Before execution, review labels and evidence, preserve family-level splits,
freeze a representative independent holdout and inspect source/artifact hashes.
Compare deterministic templates, retrieval and untuned models before deciding
whether an adapter improves a recurring error. Model agreement alone does not
approve data or justify promotion.

The pack contains `training-config.json`, `train_lora.py`, a guarded
`jupiter-auditex.sbatch` and a checksum manifest. `job_ready` means approved
train/validation/test data and an immutable base revision exist; runtime
qualification remains a separate pending requirement. Unreviewed data cannot
pass the launch guard. The default **100 optimizer steps is a pilot limit**, not
a GPU-hour estimate; preparation leaves token counts and runtime unknown.

Claude must stage the exact base checkpoint in the project Hugging Face cache,
qualify the pinned candidate dependencies on Arm64/GH200, verify the explicit
Qwen text-backbone loader and LoRA targets, then inspect a four-GPU pilot. No
dependency installation, model download or hosted-service fallback occurs in
the recipe. It refuses overlength examples instead of silently truncating them.
The candidate PyTorch 2.14.1 release has Linux Arm64 wheels, but its
[PyPI dependencies](https://pypi.org/pypi/torch/2.14.1/json) request CUDA 13
components. Check the allocated node's driver and qualified environment against
that stack; wheel availability does not qualify the cluster runtime.

For JUPITER, the template requires a qualified environment file, absolute
project cache/scratch paths, the pack path, a separate durable output directory
and an explicitly supplied Slurm account. Submit only after qualification and
pass `--runtime-qualified` explicitly. Resume uses a checkpoint beneath the
same output directory and checks base revision and pack identity in both the
run directory and the selected checkpoint. The recipe writes that identity on
each checkpoint save; checkpoints without it cannot resume through this guard.
Retain checkpoint, dataset and environment records; evaluate the exported adapter on
untouched held-out cases and its intended deployment machine before promotion.

Implementation references: [Transformers Qwen text and vision model classes](https://huggingface.co/docs/transformers/model_doc/qwen3_5),
[TRL supervised fine-tuning](https://huggingface.co/docs/trl/en/sft_trainer).
