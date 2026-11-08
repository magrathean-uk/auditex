# Assessment (ASSESS-v2)

Base: main 8b3a334. Verification line: read all 12 `.plan/work/INV-*/result.md` (dead, deps, docs, engine, gws, history, layout, mcp, product, rules, security, tests), all status done and well-formed; notes.md files not needed. Nothing was run by the slices beyond collection, so "works" means read or rg unless stated. Slice output is evidence, not truth.

## What exists
- Two engines. M365 engine `src/azure_tenant_audit/` (~43.9k lines excluding value_rules; entry `pyproject.toml:47`, `cli.py:1016`) never imports `auditex` (rg, INV-engine and INV-security). Product layer `src/auditex/` (cli.py 1454 lines, reporting.py 3835, scuba_projection.py 2214; entries `pyproject.toml:46-49`).
- Value rules: 102 policies, spec v3.9.1, 37 kinds, 33 registered plus 4 by prefix (`configs/scuba-value-rules.json`, `src/azure_tenant_audit/value_rules/__init__.py`); 194 test functions in `tests/test_value_rules_*.py`; `configs/rule-packs.json` (39 packs) from `scripts/generate-rule-packs.py`.
- Google Workspace: `src/auditex/google_workspace/` (~5.5k lines, 10 collectors, 56 `google.*` rule IDs, `findings.py` 2280); 4 test files (~4.5k lines).
- MCP: `src/auditex/mcp_server.py` (1165), `mcp_registry.py` (280): 34 tools, 7 with read_only_hint false; response tools gated by `AUDITEX_ENABLE_RESPONSE` (`features.py`, `command_builders.py:173`, `mcp_server.py:187,485`, `mcp_registry.py:251`).
- Tests: 223 `test_*.py` files, 20093 collected (19961 under default addopts) (`pytest.ini`; INV-tests). Acceptance-marked tests excluded from `make test` (`pytest.ini:3`).
- Parked model layer, still shipped and CLI-wired (`src/auditex/model_*.py`, `cli.py:1003-1043`, `scripts/*model*`, `examples/model_development/`, `configs/model-sources.json`); model_train extras exact-pinned (`pyproject.toml:36-44`).
- `tenant-bootstrap/` separate tree with its own `azure_tenant_audit/`, tests, vendored microsoft-skills (`tenant-bootstrap/vendor/microsoft-skills/`).
- Release/packaging: tags v1.2.0 to v1.2.4, `release/1.2` at c9edea5; main version 1.3.0.dev0 (`pyproject.toml:7`); 156 commits between v1.2.4 and main (INV-history).
- Gates: `Makefile:48-69` release-check, `.pre-commit-config.yaml` (ruff, gitleaks), `.gitleaks.toml`, `scripts/oss-taint-scan.sh`, `scripts/check-archive-wheel.py`.
- `.plan/` scaffold: STATE.md, master-plan.md, DECISIONS.md, BACKLOG.md, CLEANUP.md, milestones/M00-foundation.md.

## What works
- Shipped-content manifest equals pyproject data-files, 18 of 18 by AST (`src/azure_tenant_audit/shipped_content.py`, `pyproject.toml:67-95`; INV-layout, INV-dead 22 entries all exist). Parity pytest not run.
- Syntax: ast.parse of 232 Python files, 0 errors (INV-dead).
- Read guard exists at `src/azure_tenant_audit/graph.py:46-52,126-150,477-479` (read, not exercised by this session).
- `allow_abbrev=False` holds for every parser: `src/auditex/cli.py:554-555`, `guided.py:304`, `demo.py:91`, `mcp_server.py:767`, and the engine via `src/azure_tenant_audit/argument_parser.py:119` plus `cli.py:107`.
- Secrets: token writes 0600 via `secure_write_text` (`src/auditex/auth.py:231`, `google_workspace/auth.py:127`, `secret_hygiene.py:107`); `tests/conftest.py:31-43` redirects auth paths.
- Google scope sets and Gmail narrowing match the admin guide (`google_workspace/auth.py:12-36`, `docs/guides/admin-permission-guide.md:190,214`); no mutating Google calls found by rg.
- Forbidden-pattern scan of docs (workstation paths, retired domains, `contact@`) is clean (INV-docs).
- Release tags match CHANGELOG headings (`CHANGELOG.md:577-657`); 1.2.4 fixes the stale build/ tree (`CHANGELOG.md:581-586`).
- `generate-rule-packs.py --check` is wired at `Makefile:66`; its pass state is unknown (see Risks).

## What is broken
- No test, lint, smoke or release-check result exists for main; every slice declined to run them (load 22.7 on 12 cores, INV-tests).
- `Makefile:54` uses `$$TMPDIR` under `set -eu`; unset TMPDIR aborts or writes to a root path (inferred, not run; INV-deps, INV-layout; confirmed by reading).
- Three dead doc references: `docs/guides/admin-permission-guide.md:362` (`docs/prerequisites/` absent), `docs/legal/third-party-notices.md` (`skills/mcp-builder/` absent), `docs/guides/model-development.md` (`tests/providers/m365` absent).
- `scripts/oss-taint-scan.sh:39` prunes `./docs/taint`, which does not exist (harmless).
- Stale docs: `docs/reference/output-contract.md:1451` "Explainer (planned output)"; `docs/guides/ai-assessment.md:121`; `src/azure_tenant_audit/value_rules/defender_spam.py:6` "held until P4" while the config enables those rows; `docs/reference/security-privacy.md:446-447`.
- `pytest.ini:6` `norecursedirs = !Review` (inferred no-op; confirmed present).
- `auditex validate` is cited in `docs/development/scubagear-export-adapter.md:3` and `src/auditex/scubagear_export.py:837` but no such parser exists in `src/auditex/cli.py` (single-source, INV-docs).

## Dead candidates
- `benchmarks/fake_graph_benchmark.py` and `scripts/tenant-audit-flow`: no references outside `.plan/` (rg confirmed). Two slices agree. Outside-repo callers unchecked.
- `src/azure_tenant_audit/catalog.py`: no importer found in src, tests or scripts (single-source, rg re-run confirmed; string lookup not ruled out).
- `assets/auditex-logo.png`: only the `-64` variant is read (`src/auditex/explorer.py:1149`); ships by glob (single-source, inferred).
- `docs/development/scubagear-export-adapter.md`: orphan doc, adapter code is live (single-source).
- `tenant-bootstrap/azure_tenant_audit/`: 14 entries vs 83, possibly a divergent copy; tests in `tenant-bootstrap/tests/test_canonical_runtime_forwarders.py` suggest forwarders to `src/` (inferred). Treat as unresolved, not dead.
- `requirements.txt`, `tenant-bootstrap/requirements.txt`: no Makefile consumer found; other consumers unsearched (single-source).
- `scripts/build-value-rule-fixture.py`: INV-layout says no outside reference; my rg found only `tests/test_value_rules_s*.py` hits for the prefix, so the base script is unconfirmed. Unresolved.
- 195 worktrees and 88 local `wt/*` branches (`git worktree list`, `git branch`), 13 inferred merged; tip and uniqueness unchecked (INV-history).
- Not dead (corrected): `src/auditex/scubagear_prune_proof.py` (imported at `src/auditex/scubagear_export.py:30`), `google_workspace/run.py:256` `build_google_toolchain_readiness` (called at `run.py:766`), `src/auditex/model_prompt.py` (imported at `model_serving.py:28`), the parked model layer, value_rules modules found only by pkgutil discovery.
- Four schemas with no by-name reference (`schemas/blocker*.schema.json`, `capability_matrix`, `collector_result`, `report_pack`, `ai_context`) are glob-enumerated at `src/azure_tenant_audit/contracts.py:1028`; keep unless a plan retires them.

## Old plan versus reality
- Old plans named in the brief (`~/Desktop/auditex-development-plan.md`, `~/Desktop/auditex.md`) do not exist; `.plan/archive/` is absent (`ls .plan`). Working records are in `~/dev/machine/records/auditex/` (PASSOVER.md, DECISIONS.md D1-D9, development-20261107/), which INV-history did not read in full. Treat as unverified.
- Passover says no local worktrees, nine `wt/*` branches, main = 22d64f2, 1.2.3 cut without approval; reality is 195 worktrees, 88 `wt/*` branches, main 8b3a334 (INV-history).
- `.plan/` files are unfilled templates (`.plan/master-plan.md`, `STATE.md`, `DECISIONS.md`, `milestones/M00-foundation.md`); the live decision log is outside the repo.
- AGENTS.md says merges to main run `make test`; there is no CI (workflows removed in `bdd0ab1`, `docs/development/runbook.md:101`), so that gate is manual.
- Brief-era premise that the Google path answers SCuBA GWS baselines is unsupported: no `GWS.` IDs in `findings.py` or `configs/` (single-source, INV-gws).

## Contradictions
- `docs/development/runbook.md:97` omits the archive and wheel step in `Makefile:53-65` (two slices agree). `runbook.md:101` asks for a wheel and sdist build that no make target does.
- AGENTS.md "never write to a tenant" versus `graph.py:342,384` token POSTs outside `_request` (intended Entra token calls, inferred); `src/azure_tenant_audit/graph.py:46` comment names only GET and `/$batch`. Other direct session calls exist at `power_platform.py:67`, `power_bi.py:45`, `dns_lookup.py:53` (guard coverage not checked).
- `docs/reference/security-privacy.md:98` "Read-only annotations are unchanged" versus 7 of 34 tools with `read_only_hint=False` (inferred wording).
- `src/auditex/mcp_registry.py:17-24` "no tool takes a secret" versus Google tools taking key and token-cache paths (`mcp_registry.py:123,130`).
- Redaction lists differ: `src/auditex/command_runner.py:13-21` versus `google_workspace/run.py:66` (Google omits `--access-token`, `--client-secret`, `--token`; single-source, INV-product).
- `.github/SECURITY.md:22-25` lists 1.2.x supported while main is 1.3.0.dev0.
- AGENTS.md forbids held-out rows in the repo; `examples/model_development/` ships and G's 5 Nov answer says the repo may carry anything. Row content not inspected; needs G.
- Spec v3.9.1 is stated in docs but `configs/scuba-value-rules.json` carried a `spec_version` key per INV-rules, while INV-docs saw none. Inferred: INV-docs grep missed it; INV-rules is the more specific read.
- Two decision logs: `.plan/DECISIONS.md` (template) and the records log D1-D9.

## Risks
- Nothing about main is test-verified; pass state of `make test`, `contract-smoke`, rule-pack drift (`python3 -I scripts/generate-rule-packs.py --check` failed only on missing `requests` outside a venv) and release-check is unknown.
- No lock file, ranged runtime deps, `pip-audit` and ruff absent on this Mac; existence of the exact model_train pins unconfirmed (`pyproject.toml:36-44`).
- Acceptance-marked tests (`explainer_acceptance`, `value_rule_acceptance`, 26,898 vectors) run nowhere automatically.
- `tenant-bootstrap/` drift: AGENTS.md does not describe it; the taint scan prunes its vendor tree (`scripts/oss-taint-scan.sh:39-41`).
- 195 worktrees may hold unique commits; any cleanup is a reserved action. Remote and GitHub release state unverified (no ls-remote or gh run).
- `google_workspace/run.py:66` redaction list gap may leak a secret flag on the Google path (inferred; needs a test read).
- clean-development lifecycle failure from the SessionStart hook is unexplained; `doctor` shows only dot-folder WARNs (INV-history, INV-layout, INV-rules). Run an unfiltered `clean-development doctor` interactively.
- Open slice question not settled: `--client-secret` at `src/auditex/command_builders.py:188` versus the test named "never carries a client secret"; `guided.py:541` argv logging.
- No slice had status other than done.

## Suggested module ownership map
| Module | Paths | Owner | Depends on | Verification |
|---|---|---|---|---|
| m365-engine | `src/azure_tenant_audit/*.py`, `src/azure_tenant_audit/collectors/**`, `src/azure_tenant_audit/adapters/**`, `configs/*.json` except rules and model, `schemas/**` | codex | none | `.venv/bin/python -m pytest tests/test_read_guard.py` |
| value-rules | `src/azure_tenant_audit/value_rules/**`, `configs/scuba-value-rules.json`, `configs/rule-packs.json`, `scripts/generate-rule-packs.py`, `scripts/build-value-rule-fixture*.py`, `tests/test_value_rules_*.py`, `tests/fixtures/value-rules/**` | terra | m365-engine | `python3 scripts/generate-rule-packs.py --check` in venv |
| explainer | `src/azure_tenant_audit/explainer/**`, `tests/explainer_checks/**`, `tests/test_explainer_integration.py` | terra | value-rules | `.venv/bin/python -m pytest tests/test_explainer_integration.py` |
| product-cli-reporting | `src/auditex/*.py` except model, mcp and shipped items below, `src/auditex/explorer_assets/**` | codex | m365-engine | `.venv/bin/python -m pytest tests/test_cli.py tests/test_cli_abbreviations.py` |
| google-workspace | `src/auditex/google_workspace/**`, `tests/test_google_*.py`, `examples/google_workspace_sample.json` | terra | product-cli-reporting | `.venv/bin/python -m pytest tests/test_google_workspace.py tests/test_google_parity.py` |
| mcp | `src/auditex/mcp_*.py`, `src/auditex/command_builders.py`, `tests/test_mcp_*.py` | codex | product-cli-reporting | `.venv/bin/python -m pytest tests/test_mcp_guard_repair.py` |
| model-layer-parked | `src/auditex/model_*.py`, `src/auditex/external_assessments.py`, `src/auditex/assessment_*.py`, `scripts/*model*`, `scripts/*oracle*`, `scripts/*prowler*`, `scripts/score-adapter-checkpoints.py`, `examples/model_development/**`, `configs/model-sources.json` | terra | product-cli-reporting | `.venv/bin/python -m pytest tests/test_model_corpus.py` |
| tenant-bootstrap | `tenant-bootstrap/**` | terra | m365-engine | `.venv/bin/python -m pytest tenant-bootstrap/tests` (collection unverified) |
| packaging-release | `pyproject.toml`, `Makefile`, `requirements.txt`, `scripts/check-archive-wheel.py`, `scripts/oss-taint-scan.sh`, `scripts/select-python.sh`, `.pre-commit-config.yaml`, `.gitleaks.toml`, `.github/**`, `src/azure_tenant_audit/shipped_content.py` | codex | all | `make release-check` |
| docs-content | `docs/**`, `README.md`, `CHANGELOG.md`, `agent/**`, `skills/**`, `profiles/**`, `assets/**`, `examples/sample_audit_bundle/**`, `examples/demo_tenant/**` | terra | all | `.venv/bin/python -m pytest tests/test_architecture_modules.py` |
| misc-scripts | `benchmarks/**`, `scripts/tenant-audit*`, `scripts/load-local-auth.sh` | terra | none | rg reference check |

## Spot-check
Checked 15 of about 70 claims.
- `benchmarks/fake_graph_benchmark.py` unreferenced: confirmed (rg).
- `scripts/tenant-audit-flow` unreferenced: confirmed (rg).
- `catalog.py` has no importer: confirmed (rg; only a prose hit in `baselines.py:1255`).
- `scubagear_prune_proof.py` dead: CORRECTED, imported at `src/auditex/scubagear_export.py:30` and referenced by tests and docs. Applied.
- `build_google_toolchain_readiness` dead: CORRECTED, called at `run.py:766`. Applied.
- `model_prompt.py` stub dead candidate: CORRECTED, imported at `model_serving.py:28`. Applied. `evidence_db.py` exists, importer unchecked.
- `scripts/build-value-rule-fixture.py` unreferenced: CORRECTED to unresolved, rg hits are by prefix only. Applied.
- 207 worktrees: CORRECTED to 195 (`git worktree list | wc -l`); 88 `wt/*` branches confirmed. Applied.
- `allow_abbrev` coverage unverified in the engine: CORRECTED, covered at `argument_parser.py:119` and `cli.py:107`. Applied.
- tenant-bootstrap is a divergent copy: CORRECTED to unresolved, forwarder tests exist (`tenant-bootstrap/tests/test_canonical_runtime_forwarders.py`). Applied.
- `Makefile:54` `$$TMPDIR` under `set -eu`: confirmed by reading.
- No CI workflows tracked: confirmed (`git ls-files .github`).
- Token POSTs at `graph.py:342,384`: confirmed; extra direct session calls added to Contradictions.
- Three broken doc references: confirmed for `docs/prerequisites` and `skills/mcp-builder` (absent); `tests/providers/m365` not re-checked.
- Runbook omits the archive step; `pytest.ini` `!Review`: confirmed by reading.
