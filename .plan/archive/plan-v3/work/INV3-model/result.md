## RESULT INV3-model
status: done
summary: The parked model layer is nine `src/auditex/model_*.py` modules, `auditex model` CLI wiring, about 36 model and oracle scripts, the `model_train` extra, `model_development` examples, and two configs. The template explainer does not import any model module, but `reporting.py`, `scuba_projection.py`, `contracts.py` and the value rules import `model_assessment.py`, `model_evidence.py` and two `model_eval.py` helpers. `model_prompt.py` has one importer, `model_serving.py`.
summary: The brief's hint that `model_prompt.py` must stay for the explainer is not supported by the import graph.
summary: The brief's named module `model-layer-parked` does not exist; DEC-004 and BACKLOG.md:11 cite it.
summary: Nothing was built, installed or tested. The package import failed under system python3, so `auditex model sources` was not run.
summary: Full detail is in `.plan/work/INV3-model/notes.md`.
changes: `.plan/work/INV3-model/notes.md` (new, 44 lines). No repository files touched.
verification: `python3` ast parse and sha256 of `src/auditex/model_prompt.py` vs `SYSTEM_PROMPT_SHA256`: pass. `PYTHONPATH=src python3 -I -c 'from auditex...'`: fail (ModuleNotFoundError through `src/azure_tenant_audit/cli.py:15`; cause not diagnosed). `rg` import, reference and name checks: run, results as cited. Makefile target list (`rg '^(\S+):'`): 14 targets, none model-specific.
risks: Removing `model_assessment.py`/`model_evidence.py` or the `model_eval` helpers breaks the shipped report and projection path, so they need re-homing first. `Makefile:140` (contract-smoke) imports `auditex.model_serving`. `tests/test_parser_error_privacy.py` names most model scripts and may break on removal (not read).
questions_for_g: Should `model_prompt.py` be removed with the layer (only `model_serving.py` imports it), or does G want a template-explainer prompt kept? Should the removal also drop the `--endpoint`/`--model` CLI flags and the `ModelClient` path, or only the modules? Should the `model_train` extra and its `make audit-deps` entries go in the same change?

### Findings

1. exists
- Parked modules: `src/auditex/model_serving.py` 619 lines (ModelClient, assess_run, chat-completions POST); `src/auditex/model_training.py` 718; `src/auditex/model_eval.py` 417 (`_pairs` line 53, `_invalid_constant` line 62); `src/auditex/model_corpus.py` 404; `src/auditex/model_precheck.py` 156; `src/auditex/model_sources.py` 213 (reads `configs/model-sources.json` line 210); `src/auditex/model_prompt.py` 4.
- Shared with the shipped path: `src/azure_tenant_audit/model_assessment.py` 573 (`derive_explainer` line 212, `validate_explainer` line 246, schema table lines 26-32); `src/azure_tenant_audit/model_evidence.py` 3 (`NOT_COLLECTED`).
- CLI: `src/auditex/cli.py:64` subparser; `_build_model_parser` line 676; `assess` help line 684 ("The model layer is parked."); endpoint flags lines 704-709; dispatch lines 1028-1075.
- Scripts: `scripts/build-oracle-cases.py` 2855 lines; `split-oracle-cases.py` 476; `annotate-oracle-cases.py` 140; `build-model-examples.py` 279; `build-lab-model-cases.py` 178; `run-model-benchmark.py` 632; `score-model-precheck.py` 35; `score-adapter-checkpoints.py`. Oracle-adjacent: `build-prowler-cases.py`, `build-value-rule-fixture*.py` (s4-s9), `derive-scuba-projection-shapes.py`, `assess-scubagear-export.py`. Template explainer (keep): `generate-explainer.py`, `generate-explainer-baselines.py`.
- Data: `examples/model_development/` (three jsonl, 48 lines each); `configs/model-sources.json` 215; `configs/oracle-policy-map.json` 174 (used by `scripts/build-prowler-cases.py:64`, `tests/test_prowler_cases.py:24`); `tests/fixtures/model-serving-cases.jsonl`, `model-serving-v7.json`; `schemas/model_assessment*.schema.json` (five variants).
- Packaging: `pyproject.toml:36-43` (`model_train` extra), `pyproject.toml:91` (data-files), `src/azure_tenant_audit/shipped_content.py:96-100` (`model_development` area); `Makefile:52-66` (audit-deps), `Makefile:140` (contract-smoke).
- Output: `src/auditex/output_writers.py:52-53, 119-122`; `src/azure_tenant_audit/bundle_integrity.py:80`; `src/azure_tenant_audit/contracts.py:971-985`.
- Docs: `docs/guides/model-development.md` 1227 lines; `docs/provenance/provenance.md:112`; `docs/provenance/provenance.csv:43`; `docs/reference/output-contract.md`; `docs/development/runbook.md`; `docs/guides/ai-assessment.md`; `README.md`; `AGENTS.md:34`.
- Tests: 50 test files reference a `model_*` module (`rg -l`), including `tests/test_model_*.py` and `tests/test_oracle_*.py`.
- Plan: `.plan/DECISIONS.md:31-35` (DEC-004); `.plan/BACKLOG.md:11`; `.plan/ARCHITECTURE.md:9`; `.plan/milestones/M01-boundary-proof.md:8, 49-50`; `.plan/milestones/M02-docs-accuracy.md:11, 16, 50`.

2. works
- `src/auditex/model_prompt.py`: SHA-256 of `SYSTEM_PROMPT` matches `SYSTEM_PROMPT_SHA256` (ast parse plus hash, command in verification).
- Makefile has 14 targets (`rg '^(\S+):' Makefile`); none is model-specific. `audit-deps` (Makefile:52-66) is the only model-referencing target.

3. broken
- Package import failed under system python3 (`src/azure_tenant_audit/cli.py:15` chain). Not diagnosed; likely no venv (inferred).
- Stale name: `model-layer-parked` at `.plan/BACKLOG.md:11` and `.plan/DECISIONS.md:31-35` matches no path outside `.plan/archive/` (`rg`, no hits).

4. dead candidates
- `src/auditex/model_prompt.py`: only importer is `src/auditex/model_serving.py:31` (`rg 'model_prompt|SYSTEM_PROMPT'` over `src`). `src/azure_tenant_audit/explainer/*.py` has no model import (`rg`, no matches).
- `scripts/score-model-precheck.py`: referenced only by `docs/guides/model-development.md` and `tests/test_parser_error_privacy.py` (`rg -l -F`); no test runs it (inferred).
- `scripts/build-model-examples.py`: referenced only by `tests/test_parser_error_privacy.py`.
- `examples/model_development/fixture-model-a.jsonl` and `fixture-model-b.jsonl`: only the `pyproject.toml:91` glob found (inferred; not exhaustive).

5. contradictions
- DEC-004 and `.plan/BACKLOG.md:11` plan removal of the `model` CLI wiring; the code still wires it (`src/auditex/cli.py:64`, `:676`, `:1037`).
- `AGENTS.md:34` says there is "no model fallback" and the local model never decides a verdict; the endpoint flags and `ModelClient` dispatch remain (`src/auditex/cli.py:704-709`, `:1037-1051`). Default-path reachability not verified (inferred: not by default).
- `src/auditex/cli.py:64` help says "using a configured endpoint"; `cli.py:684` says "rule-only ... parked".

6. open questions
- Which `model_eval.py` and `model_assessment.py` helpers the shipped path needs: read `src/auditex/reporting.py:570-600` (imports at 577-579) and `rg 'model_eval|model_assessment'` over `src/auditex` and `src/azure_tenant_audit/value_rules`.
- Shared imports to re-home or keep: `src/auditex/scuba_projection.py:23-24`, `src/azure_tenant_audit/scuba_precheck.py:12`, `src/azure_tenant_audit/value_rules/record.py:6`, `src/auditex/scubagear_export.py:20`.
- `Makefile:140` imports `auditex.model_serving`; removal needs that line rewritten.
- `tests/test_parser_error_privacy.py`: check whether it enforces a script-name list.
- `scripts/bootstrap-local-tools.sh` (258 lines) and `scripts/load-local-auth.sh` are neighbouring auth/bootstrap areas; not settled whether model-specific.
- `docs/guides/model-development.md` and `docs/guides/ai-assessment.md` were not read in full.
- Neighbouring, outside slice: `tenant-bootstrap/` (frozen per `.plan/ARCHITECTURE.md:9`) and `benchmarks/`.
