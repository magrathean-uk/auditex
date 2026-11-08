## RESULT INV-layout
status: done
summary: Shipped-content manifest matches pyproject data-files exactly (18 of 18, checked by AST, no import). Entry points resolve to existing `main` functions. Release-check archive and wheel step is present in Makefile but missing from the runbook. Dead candidates are scripts/build-value-rule-fixture.py, scripts/tenant-audit-flow and benchmarks/fake_graph_benchmark.py. clean-development doctor shows no FAIL for this project; the SessionStart lifecycle failure is unexplained.
changes: none in the repo; wrote .plan/work/INV-layout/notes.md only
verification: `clean-development doctor` run, output head-truncated, no FAIL lines (pass with caveat); AST parse of src/azure_tenant_audit/shipped_content.py vs pyproject data-files, 18 vs 18, no mismatches (pass); rg for entry-point defs (pass); ls of scripts/ for Makefile-referenced scripts (pass); rg reference scans for dead candidates (pass); parity pytest not run; importing the package failed, system python3 lacks requests (not run)
risks: release-check's archive step uses "$TMPDIR" with no fallback (Makefile:54), and TMPDIR is unset in the GUI launchd env (inferred failure); tenant-bootstrap/azure_tenant_audit is a divergent copy (14 entries vs 83 in src), so drift is possible; pytest.ini `norecursedirs = !Review` looks like a no-op (inferred)
questions_for_g: none

### Findings

1. exists
- Entry points: pyproject.toml:46-49 (azure-tenant-audit, auditex, auditex-mcp); mains at src/azure_tenant_audit/cli.py:1016, src/auditex/cli.py:918, src/auditex/mcp_server.py:772.
- Packaging: pyproject.toml:58-86 (packages.find :61, package-data :64-65, data-files :67-86); src/azure_tenant_audit/shipped_content.py:18 onwards (18 ShippedContentArea entries).
- Makefile:5-71: test, login, lint, sample, audit-full, install, bootstrap, setup, doctor, release-check, contract-smoke.
- Build metadata: .clean-development.json (schemaVersion 2, buildDirs ["build"], depDirs [".venv"]); .gitignore:4,8,9,12,14,18; pytest.ini.
- Top-level dirs (file counts): src 223, tests 346, tenant-bootstrap 131, scripts 35, configs 21, docs 20, schemas 17, examples 15, skills 4, profiles 5, agent 2, assets 2, benchmarks 1.
- Parity test: tests/test_architecture_modules.py:236-241; also tests/test_explainer_integration.py:78-79, tests/test_scubagear_export.py:1514, tests/test_explorer_redesign.py:246.
- Release archive check: Makefile:48-69, scripts/check-archive-wheel.py, tests/test_check_archive_wheel.py.

2. works
- Entry-point functions exist: rg '^def main' (command run).
- Shipped manifest equals pyproject data-files: AST parse, python3 -I (command run; pass).
- Makefile-referenced scripts exist: ls scripts (pass).
- clean-development doctor: no FAIL lines; project-related output ok (command run; pass with truncation caveat).
- Not verified: parity pytest, release-check, contract-smoke (not run; no builds or suites allowed).

3. broken
- none confirmed.
- Inferred: Makefile:54 with TMPDIR unset writes to a root-level path (doctor reports TMPDIR unset in the launchd env; Makefile:54).

4. dead candidates
- scripts/build-value-rule-fixture.py: rg -F basename outside scripts/ and .plan/ returns nothing.
- scripts/tenant-audit-flow: same rg, nothing.
- benchmarks/fake_graph_benchmark.py: rg -F returns nothing outside .plan/.
- tenant-bootstrap/azure_tenant_audit/: 14 entries vs 83 in src/azure_tenant_audit; diff -rq 125 lines (inferred divergent copy; importers unknown).
- Dummy-tenant kit: rg -il 'dummy[- ]tenant' finds nothing outside tests/** here; kit state not in repo.
- TODO/FIXME/XXX/HACK: none in Makefile, pyproject.toml, scripts/, shipped_content.py, tenant-bootstrap/ (vendor excluded).

5. contradictions
- docs/development/runbook.md:97 omits the archive and wheel step that Makefile:48-69 runs.
- docs/development/runbook.md:101 says build wheel and sdist before tagging; no Makefile target does this (manual step).
- pytest.ini norecursedirs `!Review`: `!` is not a negation in pytest (inferred no-op).
- AGENTS.md "make lint is compileall only" matches Makefile:18-20 (no contradiction).

6. open questions
- SessionStart lifecycle failure: settle with a project-scoped `clean-development doctor` (not head-truncated) or `clean-development status` from this path.
- Is tenant-bootstrap/azure_tenant_audit imported? rg -F 'azure_tenant_audit' tenant-bootstrap/scripts tests, then the sys.path setup in tenant-bootstrap/scripts/*.
- Does pytest collect tenant-bootstrap/tests? `pytest --collect-only -q`.
- Are the two unreferenced scripts called from other scripts? rg -F inside scripts/.
- Does make release-check fail with TMPDIR unset? `echo "$TMPDIR"` in a terminal shell.
- Neighbouring area: pyproject.toml:65 names src/auditex/explorer_assets/*; existence not checked.
