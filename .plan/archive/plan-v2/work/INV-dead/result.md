## RESULT INV-dead
status: done
summary: Read-only inventory of dead code and deletion candidates in auditex (HEAD 8b3a334). Two real dead candidates: benchmarks/fake_graph_benchmark.py and scripts/tenant-audit-flow. The parked model layer is referenced, so it is not dead. No HF upload code exists in the repo, only a cache read. Evidence and the full list are in .plan/work/INV-dead/notes.md (repo-relative).
changes: none (notes written to .plan/work/INV-dead/notes.md only)
verification: rg reference searches per module and script (all 206 src modules and the scripts/benchmarks set); python3 -I ast.parse over 232 files, pass; python3 -I tomllib check of 22 pyproject data-files, pass (0 missing); Makefile path check, pass; Grep/Read of the cited lines. Not run: make test, contract-smoke, pytest, installs (outside this slice).
risks: A basename-only zero-reference search gives false zeros for dynamically named files (value_rules KINDS modules, explorer fonts, glob-shipped profiles, schemas and fixtures). Those are listed as not deletable. The tenant-bootstrap duplicate-package overlap is by basename only.
questions_for_g: Keep the parked model layer (about 2,000 lines plus builders) or retire it? Keep assets/auditex-logo.png in the shipped package?

### Findings

1. exists
- src/: 206 .py files. Parked model layer, CLI-reachable: src/auditex/model_training.py (695 lines), model_eval.py, model_precheck.py, model_prompt.py, model_serving.py, model_sources.py, model_corpus.py (393), external_assessments.py, assessment_review.py, assessment_sources.py. CLI wiring: src/auditex/cli.py:1003-1043.
- Parked scripts: scripts/score-adapter-checkpoints.py (619 lines), build-lab-model-cases.py, run-model-benchmark.py, build-model-examples.py, score-model-precheck.py, build-oracle-cases.py, split-oracle-cases.py, annotate-oracle-cases.py, build-prowler-cases.py.
- Model data: examples/model_development/ (cases.jsonl, 48 lines; two fixture-model files); configs/model-sources.json (read at src/auditex/model_sources.py:210).
- Value rules: 8 modules with module-level KINDS in src/azure_tenant_audit/value_rules/, loaded by pkgutil at src/azure_tenant_audit/value_rules/__init__.py:29-38.
- tenant-bootstrap/: separate tree, with azure_tenant_audit/ (26 .py files) and vendor/microsoft-skills/ (29 files, licensed per NOTICE:7-9).
- benchmarks/fake_graph_benchmark.py (82 lines); scripts/tenant-audit, tenant-audit-full, tenant-audit-flow (all executable).
- .plan/: CLEANUP.md (empty ledger), DECISIONS.md (template text only), BACKLOG.md (all "none").

2. works
- Syntax: python3 -I ast.parse over src/, scripts/ and benchmarks/ Python, 232 files, 0 errors.
- pyproject.toml data-files: 22 entries, all present on disk (python3 -I tomllib + glob).
- Makefile path references (scripts, tests, benchmarks, tenant-bootstrap, examples, configs, docs): all exist (rg -o + test -e; Makefile:6-71 targets).
- Shipped content is glob-based (src/azure_tenant_audit/shipped_content.py:19-22, 52, 97-100), mirrored at pyproject.toml:65-69.
- Explorer fonts load by constructed name (src/auditex/explorer.py:1124-1142), so they are live.
- guided-run exists (src/auditex/cli.py:52, 1055).
- HF: src/auditex/model_training.py:640-648 calls snapshot_download with local_files_only=True (cache read only). No upload, push_to_hub or HfApi code anywhere in the repo outside the vendor tree.

3. broken
- none found by the checks above.
- Inferred, not broken: scripts/tenant-audit-flow:13 execs `auditex.cli guided-run`, which exists.

4. dead candidates
- benchmarks/fake_graph_benchmark.py: rg -F for the file name and "benchmarks/" finds no references outside itself. Not in Makefile, pyproject or docs. Last touched 0efc032 (2026-05-06). Strong candidate.
- scripts/tenant-audit-flow (13 lines): rg -F "tenant-audit-flow" finds no references outside itself. Body is a one-line exec of `auditex guided-run`. Last touched 4705f46 (2026-04-19, "feat: add guided operator flow"). Inferred superseded alias.
- assets/auditex-logo.png: no literal reference. Code reads only assets/auditex-logo-64.png (src/auditex/explorer.py:1149). Ships via the assets/* glob (shipped_content.py:20, pyproject.toml:69). Inferred unused by code.
- Parked model layer: not dead. Reached from cli.py:1003-1043, tests (for example tests/test_score_adapter_checkpoints.py:23, tests/test_model_corpus.py:11) and docs (docs/guides/model-development.md:116, 1142-1218).
- Not deletable on this evidence (zero basename hits, but live): value_rules aad_authz, aad_pilot, aad_roles, defender_dlp, defender_phish, defender_resolution, defender_spam, exo_open; explorer fonts; tests/fixtures/powerplat (tests/test_scuba_adapters_powerplat.py:23-24); glob-shipped profiles, schemas and agent JSON.
- scripts/build-value-rule-fixture-s4, s6, s7, s9: referenced only by their own usage line and by test or doc mentions (for example tests/test_value_rules_s4.py). Inferred alive as provenance tooling.

5. contradictions
- docs/guides/ai-assessment.md:121 says "No prompt exists yet for the planned explainer", yet src/azure_tenant_audit/explainer/ exists with tests. Inferred: the explainer is template-only, so the wording is ambiguous.
- .plan/DECISIONS.md and BACKLOG.md still hold template placeholder text; CLEANUP.md ledger is empty.
- None found between README.md:135, docs/reference/security-privacy.md:38 and 451, and the code (src/auditex/model_serving.py:359; cli.py:682). Model layer is parked and not called by assessment in both.
- None found for examples/model_development/cases.jsonl (48 lines, matching docs/guides/model-development.md:36) or for cis_m365_v3 (retired, still accepted at src/azure_tenant_audit/contracts.py:98).

6. open questions
- Is tenant-bootstrap/azure_tenant_audit a fork of src/azure_tenant_audit? 23 of 26 basenames overlap; not diffed. Settle with diff -rq of the two trees.
- Does anything outside the repo call scripts/tenant-audit-flow or benchmarks/fake_graph_benchmark.py? Settle by searching ~/dev/machine helpers (neighbouring area, not searched).
- Should docs/provenance/provenance.md:90 keep the value-rule fixture builders s4 to s9? Not read.
