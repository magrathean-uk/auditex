# Assessment v4

Source: 11 slice results under `.plan/work/` (INV4-bases, INV4-d5, INV4-delta, INV4-explainer, INV4-hygiene, INV4-kit-chains, INV4-kit-data, INV4-scanners, INV4-trainer, PASS-model, PASS-airr), each `result.md`, all status done. Slices are luna evidence; unmarked claims were made by one or more slices and untested unless stated. "single-source" = one slice only. Notes files followed: none needed beyond the result text.

## What exists
- Releases: tags v1.3.0 (5f61f29) and v1.4.0; CHANGELOG.md:9 is 1.4.0 (INV4-delta, INV4-trainer; tag rev confirmed).
- Model layer removed after v1.3.0 in c97539d: 67 deleted paths between tag and HEAD (confirmed); no `src/auditex/model_*.py` at HEAD (INV4-delta, INV4-trainer).
- Rule engine: `configs/scuba-value-rules.json` answers 102 policies (confirmed); `src/azure_tenant_audit/value_rules/`; `src/auditex/rule_assessment.py:321` `assess_run`; CLI `assess` at `src/auditex/cli.py:64` (INV4-delta, INV4-explainer).
- Template explainer: `src/azure_tenant_audit/explainer/` (8 files), `configs/explainer-template.json` (1,084 cells, 102 policies), `configs/explainer-baselines.json` (109 policies, confirmed); wired into reports only, `src/auditex/reporting.py:575-602`; no MCP tool, `src/auditex/mcp_registry.py` (INV4-explainer).
- D5 name masking: `src/azure_tenant_audit/output_redaction.py` (1,909 lines; `run_salt` 278-280, `_NameMatcher` 1401-1480); `CONTRACT_VERSION = "2026-11-08"` at `src/azure_tenant_audit/contracts.py:21` (INV4-d5, single-source).
- Boundary scanners live inside tests: `tests/test_read_boundaries.py` (3,386 lines), `tests/test_http_verb_allowlist.py` (1,389 lines); runtime backstop `src/azure_tenant_audit/adapters/read_guard.py`; limits tables `docs/reference/security-privacy.md:206-245` (INV4-scanners, single-source).
- Build and gate: `Makefile` targets acceptance, lint, release-check, release-archive, dist, contract-smoke; `SOURCE_DATE_EPOCH` set at Makefile:135 (confirmed); `scripts/check-reproducible-build.py` (INV4-delta).
- Tests: about 4,204 `def test_` across 269 `tests/*.py` (grep count reproduced; not a collected count). 1,162 tracked files (INV4-delta).
- Ruff pinned 0.17.0 in `pyproject.toml:39-42` and `.pre-commit-config.yaml:16`; select E4,E7,E9,F (INV4-delta, INV4-hygiene).
- Model kit (outside repo, `~/dev/machine/work/auditex-data`, symlink to the 4TB): oracle pack v10 `kit/20261030-oracle-pack-v10/training-pack-oracle-v10-ministral3-8b/` (train 4294, validation 531, test 435); frozen test-v7; sealed AAD pilot v2.1 (487 rows) (INV4-kit-data).
- Kit chains: `kit/20261023-jupiter-deploy/run-{qualify,real,score}.sh`, `kit/20261029-round4/round4-chain.sh`, `kit/20261030-g4-8b/g4-chain.sh`, v10 stage scripts in `kit/20261030-round5-v10/tools/`; pins torch 2.14.1, transformers 5.20.1, trl 1.16.0, peft 0.21.2 (`kit/20261023-jupiter-deploy/env/requirements-jupiter-cu126.txt`) (INV4-kit-chains).
- Model of record: Ministral 3 8B, LoRA checkpoint-500, Q5_K_M (403/435 alone, 419/435 with rule pre-check); object-store and 4TB copies verified 10 Nov; never uploaded to a public hub (PASS-model; orchestrator update at its foot).
- Recoverable trainer at v1.3.0: `src/auditex/model_training.py` (718 lines, confirmed), `scripts/score-adapter-checkpoints.py` (619), `scripts/build-oracle-cases.py`, `scripts/split-oracle-cases.py`, `scripts/run-model-benchmark.py` (INV4-trainer).
- Compute research: Isambard-AI is aarch64 Grace with 4 x GH200 (96 GB H100) per node, Slurm `workq` 24 h, 32-GPU project cap, Apptainer on nodes; Dawn is x86 with Intel Max 1550 (PASS-airr, INV4-bases; `docs.isambard.ac.uk` pages, undated).
- Bases in 8-70B under Apache-2.0: Ministral 3 8B/14B, Gemma 4 12B/26B-A4B/31B, Qwen3.8-27B; Qwen 4 not released (INV4-bases, single-source, web).

## What works
- Value rules, template and what-to-collect counts reproduce: 102 policies, 1,084 cells (`configs/explainer-template.json`, `configs/explainer-what-to-collect.json`) (INV4-explainer, ran).
- Removed set is absent and `tenant-bootstrap/azure_tenant_audit/` tracks only `__init__.py` (git ls-files) (INV4-delta).
- Ruff pin equality holds (INV4-delta). Ruff W,I,B,UP gives 899 findings, 521 I001, 0 W (`pyproject.toml`; INV4-hygiene, ran).
- Explainer fixtures: 14 `.gz` files under `tests/fixtures/explainer/` (confirmed); `tests/test_explainer_fixtures.py:40-44` is a must-not-store list (INV4-hygiene).
- All 14 planted scanner tests exist by name (`tests/test_read_boundaries.py:2085-3078`, `tests/test_http_verb_allowlist.py:989-1373`) (INV4-scanners; rg only).
- Budget tests bound the D5 matcher: probes at most tokens x 6, `tests/test_redaction_scan_budget.py:328-353` (INV4-d5, read; not run).
- Kit scripts parse: `bash -n` on 8 scripts, `zsh -n` on 4; 36 `train_lora.py` are shims over `auditex.model_training` (INV4-kit-chains).
- Test-v7 and v10 test sets are byte-identical (shasum prefix 2e521987902ec2d9) (INV4-kit-data).

## What is broken
- `make lint` runs `ruff check .` after compileall (`Makefile:38-44`, confirmed); whether it passes is unrun (needs `.venv`, which exists in the main checkout only) (INV4-delta).
- Training cannot run on 1.4.0: each pack's `train_lora.py` imports the removed `auditex.model_training`; newest kit wheel is 1.2.2.dev2 (PASS-model, INV4-kit-chains).
- `tests/test_value_rules_contract.py:267-271` skips: it reads `AUDITEX_TEST_VALUE_RULE_VECTORS` and `_CATALOGUE`, while Makefile:13-14 uses `_V391` (confirmed) (INV4-hygiene).
- `src/azure_tenant_audit/bundle_integrity.py:80` still lists `model_assessment_prompts.jsonl` as an output though CHANGELOG.md:37 says it is no longer written (confirmed line; INV4-hygiene).
- `docs/development/runbook.md:122` still describes 1.3.0 publication (confirmed) (INV4-delta).
- P5 serve job timed out at 51:27 (`kit/20261027-ship-plan/PLAN-SHIP.md`); `kit/20261030-g4-8b/PACKAGE-SHA256SUMS.new` is 0 bytes; `kit/20261104-civo-pull/RUNBOOK.md:12` says 5.98 GB, parts sum 6.06 GB (INV4-kit-chains, single-source).

## Dead candidates
- `src/azure_tenant_audit/output_redaction.py:323` `_is_privileged_user`: no caller outside `.plan/` (rg confirmed) (INV4-delta).
- `Redactor.text(names=...)`, `output_redaction.py:1652`: body 1652-1677 only mentions `names` in the signature and docstring; still passed at 1732, 1785, 1789 (confirmed) (INV4-d5, INV4-hygiene).
- `tenant-bootstrap/vendor/microsoft-skills/` entries ALL-SKILLS-CATALOG, microsoft-foundry, entra-agent-id: no code reference (INV4-hygiene, single-source).
- `docs/guides/model-development.md` ("retired" page); surviving model-named tests are stale names, not dead: `tests/test_model_serving.py`, `test_model_rules_only.py`, `test_model_precheck.py`, `test_composed_model_regressions.py` (imported by `tests/test_value_rules_s6.py:181` and others) (INV4-delta, INV4-trainer).
- 7 baseline entries (109 vs 102) look unreferenced; inferred, not diffed (INV4-explainer, single-source).
- Historical schema copies `schemas/model_assessment-2026-10-2*.json` (inferred, INV4-d5).
- Kit: `kit/20261027-ship-plan/` (10.6 GB, 202,314 files, inferred), superseded v8/v10 folders (still referenced by session reviews), `kit/20261031-v11-plan/` (V11 cancelled per memory) (INV4-kit-data, INV4-kit-chains).

## Old plan versus reality
- assessment-v3 statements now false (INV4-delta, `.plan/work/assessment-v3.md`): `SOURCE_DATE_EPOCH` unset; `REASON_OUTSIDE` unused (removed); `model_serving` import in Makefile (now `rule_assessment`); tenant-bootstrap module copies (gone); `pytest.ini` norecursedirs (gone); `model` CLI wiring (now `assess`).
- BACKLOG.md:10-13 premises are wrong: fixtures "absent" (14 exist), "about 31,800" findings (899 today), contract-test catalogue (env-name mismatch, not a missing catalogue) (INV4-hygiene).
- BACKLOG's "microsoft-skills removal" premise is questioned by G-facing note (INV4-hygiene question).
- 1.4.0 delivered per DEC-011 (`.plan/DECISIONS.md:98`) (INV4-delta).
- Model plan: the model layer was parked 5 Nov and removed (DEC-005); a retraining plan reverses the 5 Nov ruling unless a new role is set (PASS-model).

## Contradictions
- `AGENTS.md:59` says `make lint` is compileall only; Makefile:38-44 also runs ruff (confirmed) (INV4-delta). AGENTS.md also omits `make acceptance` and `make dist` (runbook.md:98-110).
- DEC-011 names two decisions: scanner limits (`.plan/archive/plan-v2/DECISIONS.md:94`, confirmed) and Release 1.4.0 (`.plan/DECISIONS.md:98`, confirmed); tests cite the first (`tests/test_read_boundaries.py:13` and others) (INV4-scanners).
- Three "run salt" schemes: `output_redaction.py:278-280`, `src/auditex/scuba_projection.py:1583-1592`, `src/auditex/scubagear_export.py:291-297`; `docs/reference/output-contract.md:613-621` omits the first (INV4-d5).
- Middle initials and titles: `.plan/work/REV-M05-T03-privacy/result.md:10` versus `output_redaction.py:1177,1263-1264` (INV4-d5).
- Twin count in test-v7: 137 (`kit/20261031-v11-plan/V11-DATA-PLAN.md:12-13`, PASS-model) versus 318 of 435 by luna's longest-text heuristic (INV4-kit-data); definitions differ, unreconciled. PASS-model also says 298 twin-free, which fits neither.
- `src/auditex/model_training.py:24` default base `Qwen/Qwen3.8-27B` (confirmed at v1.3.0) versus shipped Ministral 3 8B; INV4-bases says Qwen3.8-27B exists as a repo (INV4-trainer).
- Training saves best model on eval_loss but the selector ignores eval loss (`model_training.py` ~461 versus `scripts/score-adapter-checkpoints.py:332`) (INV4-trainer, single-source).
- "model view" wording survives in `docs/reference/output-contract.md:81`, `docs/reference/security-privacy.md:31,42`, `src/auditex/scuba_projection.py:326` (INV4-hygiene).
- Kit: `kit/20261020-training-plan/TRAINING-PLAN.md:124` (100-300 GPU-h) versus `PLAN-SHIP.md:94` (100 node-h); RESULTS-round3 budget arithmetic wrong (`PLAN-SHIP.md:72`) (INV4-kit-chains).
- Removal list size: DEC-005 says 38 paths (PASS-model), luna pattern count 37, git diff 67 including DEC-006 items; exact list unread.
- Isambard: the ML-packages page both ticks pip and says no wheels are provided; GPU count 5,432 versus gov.uk 5,448 (PASS-airr).

## Risks
- Dependence on luna output: PASS-airr and INV4-bases are web-sourced, undated pages, so compute-node internet, PEFT/bitsandbytes on aarch64, and egress rules are unknown (both slices).
- No `.venv` in the slice worktrees; no test, lint or collect was run by any slice, so "works" means read or counted only (INV4-delta, INV4-d5).
- PASS-model digest is `.plan/work/PASS-model/digest.md` (untracked, in the main checkout); its pre-10 Nov statements on local copies are superseded by its own update.
- Adapter weights: object-store inner hash was verified on 10 Nov (first check); cluster scratch GGUF copy has a 90-day purge (PASS-model).
- Hook-reported clean-development registration failure; three slices did not run `doctor` (not authorised); G decides.
- Open slice gaps, not statuses: none malformed; all slices done. Unresolved questions: 7 baseline keys, customer-pack use of `policy_explanations`, Google Workspace has no value-rule path (rg unrun), D5 suite pass at HEAD, 137 vs 318 twins, whether `make lint` passes.

## Suggested module ownership map
| Module | Paths | Owner | Depends on | Verification |
|---|---|---|---|---|
| M365 engine, redaction, contracts | `src/azure_tenant_audit/**` except `explainer/`, `value_rules/`, `adapters/` | terra | none | `.venv/bin/python -m pytest tests/test_redaction_person_names.py tests/test_redaction_scan_budget.py tests/test_redaction_profiles_d3.py` |
| Value rules and explainer | `src/azure_tenant_audit/explainer/**`, `src/azure_tenant_audit/value_rules/**`, `configs/scuba-value-rules.json`, `configs/explainer-*.json`, `tests/test_value_rules_*.py`, `tests/test_explainer_*.py`, `tests/explainer_checks/**`, `tests/fixtures/explainer/**` | codex | engine | `python3 scripts/generate-rule-packs.py` (no drift); `make acceptance` |
| Product layer and reporting | `src/auditex/**` except `google_workspace/` | terra | engine | `.venv/bin/python -m pytest tests/test_cli.py -k offline`; `make contract-smoke` |
| Google Workspace | `src/auditex/google_workspace/**` | codex | product layer | focused tests (path unconfirmed) |
| Boundary scanners | `tests/test_read_boundaries.py`, `tests/test_http_verb_allowlist.py`, `src/azure_tenant_audit/adapters/**` | codex | engine | `.venv/bin/python -m pytest tests/test_read_boundaries.py tests/test_http_verb_allowlist.py` |
| Build, release, hygiene | `Makefile`, `pyproject.toml`, `.pre-commit-config.yaml`, `scripts/**`, `docs/development/**`, `AGENTS.md`, `CHANGELOG.md` | terra | none | `make lint`; `make release-check` |
| Tenant bootstrap and vendor | `tenant-bootstrap/**` | codex | none | `.venv/bin/python -m pytest tests/test_tenant_bootstrap_forwarder.py` |
| Docs and schemas | `docs/reference/**`, `docs/guides/**`, `schemas/**`, `configs/report-sections.json` | terra | engine | shipped-content parity test (`shipped_content.py`) |
| Model kit (outside repo) | `~/dev/machine/work/auditex-data/kit/**` | codex | v1.3.0 trainer, AIRR research | `bash -n` on chain scripts; `round4-chain.sh --dry-run` |

## Spot-check
13 of about 110 claims checked (12 percent).
- `_is_privileged_user` only at `output_redaction.py:323`: confirmed.
- `Redactor.text` ignores `names`; callers 1732, 1785, 1789: confirmed (other `names=True` hits at 720, 1614 are `_collect`).
- `make lint` runs compileall plus `ruff check .` (Makefile:38-44) versus `AGENTS.md:59`: confirmed; slice wording "now runs ruff" omitted compileall, applied.
- 14 `.gz` under `tests/fixtures/explainer`: confirmed.
- `tests/test_value_rules_contract.py:268-269` env names and skip: confirmed.
- `runbook.md:122` says 1.3.0 publication: confirmed.
- `bundle_integrity.py:80` lists `model_assessment_prompts.jsonl`: confirmed.
- v1.3.0 is 5f61f29, 67 deletions, `DEFAULT_BASE_MODEL` Qwen at `model_training.py:24`: confirmed.
- Baselines 109 and value-rule policies 102: confirmed.
- `.plan/DECISIONS.md:98` DEC-011 is Release 1.4.0 and `.plan/archive/plan-v2/DECISIONS.md:94` is the scanner decision: confirmed.
- `Makefile:135` sets `SOURCE_DATE_EPOCH`: confirmed.
- Test count 4,204 across 269 files: confirmed by grep (270 files in `ls tests/*.py`, a one-file difference; reported as about).
- INV4-delta "`.venv` missing": correct for its worktree; the main checkout has `.venv/bin`. Applied in Risks.
- Corrections: 2 (lint description; `.venv` scope). Not rechecked: web claims, kit contents, twin counts.
