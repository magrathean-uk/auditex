## RESULT INV-engine
status: done
summary: The M365 engine slice is about 43.9k lines in `src/azure_tenant_audit/` (excluding `value_rules/`), with 22 configs, 17 schemas and 262 test files. The engine does not import `auditex`, and the read-only guard is in place at `graph.py:126-150` and `graph.py:477-479`. No test, build or CLI run was done (brief forbids it), so "works" rests on reading and rg. Zero TODO/FIXME markers in the slice. Token POSTs bypass the Graph guard by design (inferred).
changes: `.plan/work/INV-engine/notes.md` (new; full evidence)
verification: `clean-development doctor` - ok (host WARNs noted, not slice); `rg` engine-to-auditex import check - no matches (pass); `find ... | wc -l` and `git log --oneline -n 25` on slice paths - ok; Grep/Glob/Read for the rest. No tests, builds or installs run.
risks: Token POSTs at `graph.py:342` and `:384` sit outside `_request`/`_enforce_read_only` (inferred intended, unverified). Four schemas have no by-name consumer but are enumerated by glob (`contracts.py:1028`). `catalog.py` has no importer found.
questions_for_g: none

### Findings

1. exists
- Engine: `src/azure_tenant_audit/`, about 43,930 lines excluding `value_rules/` (`find | wc -l`). Largest: `findings.py` 4477, `normalize.py` 3205, `identity_controls.py` 1633, `baselines.py` 1331, `output_redaction.py` 1313, `cli.py` 1083, `contracts.py` 1029, `graph.py` 866.
- Sub-packages: `collectors/`, `adapters/` (`read_guard.py` 435 lines), `explainer/`.
- Entry point: `pyproject.toml:47` (`azure-tenant-audit = "azure_tenant_audit.cli:main"`); `src/azure_tenant_audit/cli.py:1016`.
- Read guard: `src/azure_tenant_audit/graph.py:46-52` (`READ_ONLY_METHODS = {"GET"}`), `graph.py:126-150`, `graph.py:477-479`.
- Schema manifest: `src/azure_tenant_audit/contracts.py:1026-1029` (glob of `schemas/*.schema.json`).
- Configs: 22 files in `configs/` (listed in notes section 1).
- Schemas: 17 files in `schemas/` (listed in notes section 1).
- Tests: 262 `.py` files under `tests/`, including `tests/explainer_checks/`.

2. works
- Engine does not import `auditex`: `rg -n "^\s*(from|import) auditex|azure_tenant_audit.*auditex|from auditex" src/azure_tenant_audit --glob '!**/value_rules/**'` returned no lines.
- Entry point declared (`pyproject.toml:47`) and `main` defined (`cli.py:1016`). Not executed.
- Read guard confirmed by reading `graph.py:126-150` and `graph.py:477-479`. Not exercised by a test this session.
- Every Grep-checked engine module has at least one importer, except `catalog.py` (see 4).
- Git: 25 recent commits touch the slice; latest `36275fa Fix partner domain review findings`.

3. broken
- none confirmed by reading.
- Token acquisition uses `self.session.post` directly at `graph.py:342` and `graph.py:384`, not through `_request`. Target is `TOKEN_URL_TEMPLATE` (`graph.py:259-263`). Inferred: intended Entra token call.

4. dead candidates
- `src/azure_tenant_audit/catalog.py`: no `from .catalog`, `import catalog` or `azure_tenant_audit.catalog` found in src, tests or scripts. Inferred dead; string or CLI lookup not ruled out.
- `src/azure_tenant_audit/selection.py`: importers not confirmed (only `selection.py:5` `.presets` seen).
- `src/azure_tenant_audit/evidence_gates.py`: imports `capability_gate` (`evidence_gates.py:6`); its own importers not checked.
- Schemas with no by-name reference outside themselves: `schemas/blocker.schema.json` and `schemas/blockers.schema.json` (self-reference only, `blockers.schema.json:5`); `schemas/capability_matrix.schema.json`, `schemas/collector_result.schema.json`, `schemas/report_pack.schema.json`, `schemas/ai_context.schema.json` (no matches). Caveat (inferred): enumerated by glob at `contracts.py:1028`, never validated by name.
- Markers: zero TODO, FIXME, HACK or XXX in the slice (the single `XXX` hit is `src/azure_tenant_audit/secret_hygiene.py:65`, a `\uXXXX` escape comment).

5. contradictions
- `src/azure_tenant_audit/graph.py:46` says the audit plane sends only GET and `/$batch` POST. Token POSTs at `graph.py:342` and `:384` are a third POST path the comment does not name.
- `tenant-bootstrap/azure_tenant_audit/cli.py:185` imports `.secret_hygiene`, so a vendored copy of the package exists and may have drifted. Neighbouring area, not checked.

6. open questions
- Are `graph.py:342` and `:384` the only calls bypassing `_request`? Settle: `rg -n "session\.(post|get|request|put|patch|delete)\(" src/azure_tenant_audit`.
- Are the four unreferenced schemas validated anywhere? Settle: `rg -n "schema_dir|list_resource_files|\.schema\.json" src tests` and read the consumer of `contract_schema_manifest`.
- Does `catalog.py` have a live consumer? Settle: `rg -n "catalog" src/azure_tenant_audit/cli.py src/auditex` and `tests/test_architecture_modules.py`.
- Do the `blocker`/`blockers` schemas have a consumer? Settle: `rg -n "blocker" src tests scripts`.
- Per-area test coverage needs `pytest --cov` (not run; brief forbids test suites).
- Neighbouring: `tenant-bootstrap/` vendored package drift from `src/azure_tenant_audit/`.
