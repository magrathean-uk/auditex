# Assessment v3 (HEAD 58084bb, version 1.3.0)

Inputs read: `.plan/work/INV3-{acceptance,bootstrap,build,d5,dead,hygiene,lint,model}/result.md` (all 8, all status done, none malformed). Notes files not opened except via spot-check. Nothing was built or tested by any slice; "works" means read or hash-checked, not run. INV3-hygiene gave only a summary (its Findings point at notes.md), so its claims are single-source and thinner.

## What exists
- Value-rule replay: `tests/test_value_rules_replay.py` (full replay at :219, env `AUDITEX_TEST_VALUE_RULE_VECTORS_V391` at :53), repo sample `tests/fixtures/value-rules/vectors-v391-sample.jsonl.xz` plus manifest, builder `scripts/build-value-rule-sample-v391.py`. Full kit (26,898 vectors) lives outside the repo on the 4TB (INV3-acceptance).
- Explainer acceptance: `tests/explainer_checks/` (~6,100 lines, run recipe `README.md:21-29`), `tests/test_explainer_integration.py:402,413`. `pytest.ini:2` excludes both acceptance markers by default.
- Lab kit `tenant-bootstrap/` (131 tracked files): 26-module `azure_tenant_audit/` forwarder package, 25 scripts, 7 test files (55 tests), `vendor/microsoft-skills/` (11 SKILL.md) (INV3-bootstrap).
- Build: `Makefile:104-118` `dist`, `Makefile:88-101` `release-archive`, `scripts/check-reproducible-build.py` (72 lines), `tests/test_check_reproducible_build.py`, `docs/development/runbook.md:97-110` (INV3-build).
- D3 redaction: `src/azure_tenant_audit/output_redaction.py` (1406 lines; profiles at L24-27), `src/azure_tenant_audit/output_writers.py`, tests `tests/test_redaction_*.py`, `tests/test_notify_redaction.py`; second pseudonym helper `src/auditex/scuba_projection.py:1534-1554` (INV3-d5).
- Unmerged D5 attempt: branch `wt/redact-person-names` (tip 3e495d6, merge-base eecad1d, 12 files +3129/-115; adds `redaction_key.py`, `tests/test_redact_person_names.py`), still held by another worktree (INV3-d5).
- Parked model layer: `src/auditex/model_{serving,training,eval,corpus,precheck,sources,prompt}.py`, `src/azure_tenant_audit/model_{assessment,evidence}.py`, CLI wiring `src/auditex/cli.py:64,676,704-709,1028-1075`, ~36 oracle/model scripts, `examples/model_development/`, `configs/model-sources.json`, `pyproject.toml:36-43` extra `model_train`, 50 test files reference `model_*` (INV3-model).
- Lint: ruff configured at `pyproject.toml:57` (E4,E7,E9,F) and pre-commit hook v0.17.0 in `.pre-commit-config.yaml`; `make lint` is compileall only (`Makefile:19-20`). 595 Python files: tests 312, src 211, tenant-bootstrap 45, scripts 26, benchmarks 1 (INV3-lint).
- Hygiene: `scripts/oss-taint-scan.sh`; no `.github/workflows` (only dependabot, CONTRIBUTING, templates).

## What works
- Kit hashes (`vectors.jsonl`, `a2-vectors.jsonl`, `a2-label-overrides.jsonl`) equal the pins at `tests/test_value_rules_replay.py:163-165`; repo sample equals `manifest-v391-sample.json` (shasum, INV3-acceptance).
- `scripts/tenant-audit-flow:13` execs `guided-run`, defined at `src/auditex/cli.py:54`, dispatched `:1085` (INV3-dead).
- `src/auditex/model_prompt.py` SYSTEM_PROMPT hash matches its pinned constant (INV3-model, single-source).
- Forwarder: `tenant-bootstrap/azure_tenant_audit/__init__.py:9-10` inserts `src/azure_tenant_audit` at the front of `__path__`, `:12` imports `.cli`; `bash -n` passes on 4 shell scripts (INV3-bootstrap).
- `bash scripts/oss-taint-scan.sh` exits 0; no referenced file missing (INV3-hygiene, single-source).
- `Makefile:140` contract-smoke exercises `assess_run` in rules-only mode (asserts `model_name == "rules-only"`), so it depends on `auditex.model_serving`.
- Not run by anyone: full replay, explainer acceptance, `make test`, `make lint`, `make dist`.

## What is broken
- `make dist` is not byte-reproducible: no `SOURCE_DATE_EPOCH` pinned (`Makefile:104-118`, rg no hits); per `.plan/work/M03-T05/notes.md` (cited by INV3-build, not re-run) sdist hashes differ even with the epoch set.
- `scripts/check-reproducible-build.py:66` compares sdist members and digests only, so the gate "reproducible build ok" does not prove byte-identical sdists; runbook `:101,106` overstates it.
- Ruff pinned 0.17.0 reports 230 findings in 54 files (tests 196, src 34; E701 99, F811 42); the pre-commit hook would fail any commit touching them (inferred). Ruff is not in `.venv` (INV3-lint).
- D3 name discovery is privileged-only (`output_redaction.py:391-422`, `_is_privileged_user` L314-324): free-text names of ordinary users are not masked; docs admit it at `docs/reference/security-privacy.md:481` (INV3-d5).
- Stale plan names: `model-layer-parked` (`.plan/BACKLOG.md:11`, `.plan/DECISIONS.md:31-35`) matches no path outside `.plan/archive/`.
- Package import failed under system python3 in INV3-model (`src/azure_tenant_audit/cli.py:15`, undiagnosed, probably no venv; inferred).

## Dead candidates
- `benchmarks/fake_graph_benchmark.py`: no reference outside itself (INV3-dead; confirmed by spot-check).
- `scripts/tenant-audit-flow`: no reference anywhere in repo outside `.plan/` (confirmed). External callers unsearched.
- `assets/auditex-logo.png`: no literal reference; code reads `assets/auditex-logo-64.png` (`src/auditex/explorer.py:1169`); ships via `assets/*` glob (inferred, confirmed no refs).
- `requirements.txt` and `tenant-bootstrap/requirements.txt`: no tool consumer; mentioned only descriptively in `docs/legal/third-party-notices.md:65` and `NOTICE`; `pyproject.toml` carries the same ranges.
- `tenant-bootstrap/scripts/{auth-lab-populator.py,create-lab-populator-app.py,run-auditor.sh}`: 0 references (INV3-bootstrap, single-source).
- `tenant-bootstrap/azure_tenant_audit/*` 23 divergent modules: shadowed while `src/` exists (inferred); tests in `tests/test_vendored_cli_abbreviations.py:19` and `tests/test_parser_error_privacy.py:32,715` still treat them as the CLI under test.
- `src/auditex/model_prompt.py`: only importer is `src/auditex/model_serving.py:31` (plus `tests/test_model_serving.py:21`); explainer does not import it (confirmed).
- `src/azure_tenant_audit/output_redaction.py:455` `REASON_OUTSIDE`: only the definition (confirmed; inferred unused; do not confuse with `REASON_OUTSIDE_RUN` in `evidence_refs.py`).
- `scripts/score-model-precheck.py`, `scripts/build-model-examples.py`, `examples/model_development/fixture-model-{a,b}.jsonl`: referenced only by docs, the glob, or `tests/test_parser_error_privacy.py` (INV3-model, inferred).
- `vendor/microsoft-skills` ALL-SKILLS-CATALOG, microsoft-foundry, entra-agent-id: docs and taint-scan references only (single-source).
- NOT dead (earlier plans wrong): `src/azure_tenant_audit/catalog.py` (imported by `tests/test_architecture_modules.py:246`, `tests/test_directory_relationships.py`; confirmed) and `scripts/build-value-rule-fixture.py` (loaded by `-s4` to `-s9` builders).

## Old plan versus reality
- `.plan/work/INV-dead/result.md`, `ASSESS-v2/result.md:20` and `assessment.md:95-96` call `catalog.py` unreferenced; wrong (test-only use). `INV-layout/result.md:3` calls `build-value-rule-fixture.py` dead; wrong.
- DEC-004 and `.plan/BACKLOG.md:11` plan removal of `model` CLI wiring; code still wires it (`src/auditex/cli.py:64,676,1037`).
- M03 said reproducible build gate; reality is members-only comparison (`scripts/check-reproducible-build.py:66`).
- `.plan/DECISIONS.md:9` cites "D6 keeps D5 out" but no numbered D6 entry exists (only that line matches `D6`; also `master-plan.md:28,55`, `BACKLOG.md:12`, `CHANGELOG.md:20`).
- D5 work exists only on unmerged `wt/redact-person-names`; `BACKLOG.md:12` holds the D5-v2 spec.
- `.plan/work/CLEAN-01-verify/result.md:12` cites `security-privacy.md:178`; the benchmarks sentence is at `:195`.

## Contradictions
- `docs/guides/model-development.md:148` names `AUDITEX_TEST_VALUE_RULE_VECTORS`; test reads `..._V391` (`tests/test_value_rules_replay.py:53`; confirmed).
- `docs/development/runbook.md` has no acceptance section; no Makefile target runs either acceptance job.
- `AGENTS.md:34` "no model fallback" versus live `--endpoint`/`--model` flags and `ModelClient` dispatch (`src/auditex/cli.py:704-709,1037-1051`); default path reachability unverified.
- `src/auditex/cli.py:64` help ("using a configured endpoint") versus `:684` ("parked").
- `AGENTS.md` has no tenant-bootstrap section; README/docs describe it as lab-only and writable (`README.md:19`, `docs/index.md:41`, `docs/development/runbook.md:118`); `.plan/ARCHITECTURE.md:9` calls it frozen; `CHANGELOG.md:655` says "own copy" of the CLI.
- `docs/reference/security-privacy.md:466-469` gives HTML peaks of 0.5 and 1.5 GiB; no harness in repo (single-source).
- Two pseudonym implementations (`output_redaction.py:264`, `scuba_projection.py:1534`); docs describe one (single-source).
- `tests/test_explainer_fixtures.py:43` names `.gz` fixtures absent at top level of `tests/fixtures/explainer/` (confirmed; may live in subdirectories, unchecked).
- `pytest.ini:4` `norecursedirs = !Review` matches no directory and may drop pytest defaults (inferred; INV3-acceptance and INV3-hygiene agree).

## Risks
- No acceptance job (value replay, explainer, `make test`, `make dist`) was run in this inventory; all "works" is static.
- Removing `model_assessment.py`, `model_evidence.py` or two `model_eval.py` helpers breaks reporting/projection (`src/auditex/reporting.py:577-579`, `scuba_projection.py:23-24`, `value_rules/record.py:6`, `scuba_precheck.py:12`, `scubagear_export.py:20`); `Makefile:140` imports `model_serving`.
- `tests/test_parser_error_privacy.py` names many model scripts and tenant-bootstrap CLI; removals may break it (not read).
- Lint: 230 existing findings block commits touching those files; broader rule set is ~31.8k findings (INV3-lint).
- Standalone `tenant-bootstrap/` outside the repo root falls back to divergent copies (`__init__.py:6`, inferred).
- Full replay depends on a kit outside the repo (4TB); kit `build_vectors.py` regeneration unverified.
- Dead verdicts cover this repo only; `~/dev/machine` helpers and external callers not searched.
- INV3-hygiene is thin (summary only); its claims are single-source.
- Open questions: standalone kit still shipped; D5 scope (all users or privileged only); remove `model_prompt.py` and CLI flags with the layer; rule set and target-version for ruff; sdist byte gate; `clean-development doctor` for failed lifecycle registration (brief forbids running it).

## Suggested module ownership map
| Module | Paths | Owner | Depends on | Verification |
|---|---|---|---|---|
| m365-engine | `src/azure_tenant_audit/**` except value_rules, redaction, model files | terra | configs, schemas | `.venv/bin/python -m pytest tests/test_cli.py -k offline`; `make contract-smoke` |
| value-rules | `src/azure_tenant_audit/value_rules/**`, `configs/scuba-value-rules.json`, `tests/test_value_rules_*.py`, `tests/fixtures/value-rules/**` | codex | m365-engine | `python3 scripts/generate-rule-packs.py` no drift; replay command in INV3-acceptance |
| redaction-d5 | `src/azure_tenant_audit/output_redaction.py`, `src/azure_tenant_audit/output_writers.py`, `tests/test_redaction_*.py`, `tests/test_notify_redaction.py` | codex | m365-engine, product-layer | `pytest tests/test_redaction_profiles_d3.py` |
| product-layer | `src/auditex/**` except model_*.py and output_writers.py | terra | m365-engine | `make test` |
| model-layer | `src/auditex/model_*.py`, `src/azure_tenant_audit/model_*.py`, `scripts/*model*`, `scripts/*oracle*`, `examples/model_development/**`, `tests/test_model_*.py`, `tests/test_oracle_*.py` | codex | value-rules, product-layer | `pytest tests/test_model_rules_only.py`; `make contract-smoke` |
| explainer | `src/azure_tenant_audit/explainer/**`, `tests/explainer_checks/**`, `tests/fixtures/explainer/**` | codex | m365-engine | README recipe `tests/explainer_checks/README.md:21-29` |
| tenant-bootstrap | `tenant-bootstrap/**` | terra | m365-engine (forwarder) | `bash -n` on its shell scripts; its tests |
| build-release | `Makefile`, `pyproject.toml`, `scripts/check-*.py`, `scripts/release-smoke.sh`, `tests/test_check_reproducible_build.py`, `.pre-commit-config.yaml` | terra | all | `make release-check` |
| hygiene-dead | `benchmarks/**`, `scripts/tenant-audit-flow`, `assets/**`, `requirements.txt`, `scripts/oss-taint-scan.sh`, `pytest.ini` | terra | none | `bash scripts/oss-taint-scan.sh` |
| docs | `docs/**`, `README.md`, `CHANGELOG.md`, `AGENTS.md` | terra | all | read-through; shipped-content parity test |

Globs are by prefix; where a broader glob overlaps a narrower row (for example `src/azure_tenant_audit/**`, `src/auditex/**`, `scripts/*`), the narrower row wins and the broad row's "except" list applies (inferred, not mechanically checked).

## Spot-check
- `catalog.py` test-only use: confirmed (rg lists `tests/test_architecture_modules.py`, `tests/test_directory_relationships.py`).
- `benchmarks/fake_graph_benchmark.py` unreferenced: confirmed (rg over repo outside `.plan`, no hits).
- `scripts/tenant-audit-flow` unreferenced: confirmed.
- `model_prompt.py` sole src importer: confirmed (`src/auditex/model_serving.py:31`); also imported by `tests/test_model_serving.py:21`, added.
- Forwarder: corrected line numbers (slice said `:7-13`; actual insert at `:9-10`, import `:12`). Applied.
- No `.github/workflows`: confirmed.
- `Makefile:140` imports `model_serving`: confirmed.
- `REASON_OUTSIDE` single definition: confirmed.
- `docs/guides/model-development.md:148` env var name: confirmed.
- No `SOURCE_DATE_EPOCH` in Makefile or pyproject: confirmed.
- `pytest.ini` `norecursedirs = !Review`: confirmed.
- DECISIONS.md has no D6 entry: confirmed (only line 9).
- `assets/auditex-logo.png` no references: confirmed.
- Root `requirements.txt` mention: corrected (slice said only third-party-notices; `NOTICE` also names it). Applied.
- Explainer `.gz` fixtures absent at top level: confirmed.
- Not rechecked (cost): ruff counts, kit hashes, D5 branch stats, M03-T05 hashes (all single-slice, run or git-derived).
- Corrections: 2. Claims checked: 15 of ~60 (about 25 percent).
