## RESULT INV4-trainer
status: done
summary: Tag v1.3.0 is 5f61f29. The DEC-005 model layer is 37 paths by pattern, against 38 in DEC-005; the exact list file is not in this worktree. The trainer is `model_training.py` (718 lines) plus its scorer, benchmark and split scripts, with a `model_train` extra and no console script. Recorded recipe: LoRA r16, alpha 32, LR 1e-4, 2 epochs; checkpoint choice by a strict-pass noise band, not eval loss. One stale default (Qwen3.8-27B) conflicts with the shipped Ministral base.
changes: none
verification: git rev-parse, git ls-tree, git diff --diff-filter=D, git show plus rg/wc on the v1.3.0 blobs, git grep for imports and flags, git show HEAD:pyproject.toml | rg; all pass. No builds, tests, checkouts or tenant contact.
risks: Exact DEC-005 list unresolved (37 vs 38). The Qwen default may be stale. Several model-named tests and docs survive at HEAD, with status unchecked.
questions_for_g: none

### Findings

1. exists
- Removed after v1.3.0, model layer (inferred from pattern): `src/auditex/model_{training,corpus,eval,precheck,prompt,serving,sources}.py`, `src/azure_tenant_audit/model_evidence.py`, 9 scripts under `scripts/` (`build-oracle-cases`, `split-oracle-cases`, `score-adapter-checkpoints`, `run-model-benchmark`, `score-model-precheck`, `annotate-oracle-cases`, `build-lab-model-cases`, `build-model-examples`, `build-prowler-cases`), `configs/model-sources.json`, `configs/oracle-policy-map.json`, 3 files under `examples/model_development/`, 15 model tests and fixtures (`git diff --name-status --diff-filter=D v1.3.0 HEAD`). Total 67 deleted paths, including DEC-006 items.
- Removal commit: c97539d, 84 files, +511/-20092 (`git show --stat`).
- Trainer core: `src/auditex/model_training.py` (718 lines). Offline case curation, `prepare_training_pack` (~line 409), `validate_training_pack` (~505), `training_main` (~627). Flags: `--pack-dir`, `--output-dir`, `--resume-from-checkpoint`, `--runtime-qualified`.
- Scorer and selector: `scripts/score-adapter-checkpoints.py` (619 lines). `SELECTION_RULE` at lines 43-68, `select_checkpoint` at 331. Flags at 588-602, including `--base-model` (40-char `--revision`), `--cases`, `--splits`, `--output-dir`, `--device`, `--dtype`, `--batch-size`.
- Oracle miner: `scripts/build-oracle-cases.py`, needs a ScubaGear checkout and OPA (flags at 2775-2789).
- Split: `scripts/split-oracle-cases.py` (flags at 413-423).
- Benchmark: `scripts/run-model-benchmark.py` (flags at 581-603).
- Precheck: `scripts/score-model-precheck.py` (flags at 18-22).
- Config: `configs/model-sources.json` (13114 bytes, `assembly_method` names Ministral 3 8B Instruct).
- Packaging: `pyproject.toml` `[project.optional-dependencies] model_train` at lines 37-43 (torch 2.14.1, transformers 5.20.1, trl 1.16.0, peft 0.21.2, accelerate 1.15.0, datasets 5.1.0). `[project.scripts]` at lines 52-55 has no training entry.

2. works
- Tag resolves to 5f61f29 (`git rev-parse --short v1.3.0`).
- 67 deletions between tag and HEAD (`git diff --name-status --diff-filter=D v1.3.0 HEAD`).
- `model_training.py` is 718 lines at the tag (`git show "v1.3.0:src/auditex/model_training.py" | wc -l`).
- The `model_train` extra exists at the tag and not at HEAD (`git show v1.3.0:pyproject.toml`; `git show HEAD:pyproject.toml | rg`).
- Recipe values read from `model_training.py:449-465` (`git show` plus `sed -n`).
- Selection rule read from `score-adapter-checkpoints.py:43-68` (`git show` plus `rg`).
- Cross-package imports listed from `git grep -n -E '^\s*(from|import) (auditex|azure_tenant_audit)' v1.3.0`.

3. broken
- none. No failing command. HEAD has no live reference to the removed names except `Makefile:165`, a negative assertion that no `auditex.model_*` module loads (`git grep` over HEAD excluding `.plan` and `.md`).

4. dead candidates
- none confirmed. Surviving model-named files at HEAD (`docs/guides/model-development.md`, `tests/test_model_precheck.py`, `tests/test_model_rules_only.py`, `tests/test_model_serving.py`, `tests/test_composed_model_regressions.py`, `tests/test_value_rules_oracle.py`, `tests/fixtures/model-serving-cases.jsonl`, `schemas/model_assessment*.json`) are not confirmed dead. Their status is unchecked (`git ls-tree -r --name-only HEAD | rg`).

5. contradictions
- `src/auditex/model_training.py:24` sets `DEFAULT_BASE_MODEL = "Qwen/Qwen3.8-27B"`. `configs/model-sources.json` `assembly_method` at the tag says Ministral 3 8B Instruct. The default looks stale (inferred; the base is passed per run).
- Training config sets `load_best_model_at_end` on `eval_loss` (`model_training.py` ~461). `score-adapter-checkpoints.py:332` says eval loss is not an input to selection. These are two selection layers, and the slice does not say which one produced the shipped adapter.

6. open questions
- Exact 38 DEC-005 paths: read `.plan/work/M02-T01/removal-list.txt` from the main checkout, or `git show c97539d^:.plan/work/M02-T01/removal-list.txt`. Settles 37 vs 38.
- Whether `Qwen/Qwen3.8-27B` exists and was ever used: needs the Hugging Face index (no network used).
- Purpose of `model_sources.py`, `model_corpus.py`, `model_prompt.py`, `model_serving.py`, `configs/oracle-policy-map.json` and the examples: described from `.plan/CLEANUP.md` only, not read.
- Whether HEAD replacements cover every cross-package import in the findings: needs an import scan at HEAD.
- Neighbouring area: `src/azure_tenant_audit/model_assessment.py` and `schemas/model_assessment*.json` survive at the tag and HEAD. They belong to the explainer side, not the trainer.
