## RESULT INV-rules
status: done
summary: 102 policies, 37 kinds, all resolved; 33 registered KINDS plus 4 dispatched by prefix; no stubs or TODO markers in the slice. Drift check and package import are unverified because the system Python lacks `requests`. One stale docstring contradicts the held-rows README.
changes: none (notes written to .plan/work/INV-rules/notes.md)
verification: `python3 -I` json load of configs/scuba-value-rules.json (102 policies, kinds), static `ast` scan of KINDS (33 registered, no duplicates), `rg` marker scan (no matches), `git log` on slice paths, `clean-development doctor` (no FAIL lines), `python3 -I scripts/generate-rule-packs.py --check` (FAILED: ModuleNotFoundError requests; not rerun)
risks: pack drift check and value-rule tests unverified in this session; the `not_assessed` path (25 lines) not analysed; `aad_authz.py` has no name-based imports and depends on registry discovery
questions_for_g: none

### Findings
1. exists
- value_rules/: 22 files, 4,250 lines (value_rules/__init__.py, catalogue.py, gates.py, helpers.py, record.py plus 15 rule modules) [src/azure_tenant_audit/value_rules/]
- configs/scuba-value-rules.json: 21,710 lines; policies 102; spec_version v3.9.1; scubagear_revision 2446ad72 [configs/scuba-value-rules.json]
- configs/rule-packs.json: rules 5, packs 39 [configs/rule-packs.json]
- scripts/generate-rule-packs.py: 48 lines; --check writes nothing, exits 1 on drift [scripts/generate-rule-packs.py:29-42]
- generator inputs present: configs/finding-templates.json, configs/control-mappings.json
- 194 test functions in tests/test_value_rules_*.py; 23 fixture entries [tests/fixtures/value-rules/]
- release path: Makefile:66 runs the --check [Makefile:66]
- shipped-content parity by glob configs/*.json [pyproject.toml:70, src/azure_tenant_audit/shipped_content.py:19]

2. works
- 102 policies, all MS. prefix; `python3 -I` json load of configs/scuba-value-rules.json
- 33 registered KINDS, no duplicates; config uses 37 kinds; 4 resolved by prefix in value_rules/__init__.py:_kind; static `ast` scan of all value_rules/*.py
- Top kinds: ca_exists 10, any_flag 8, priv_roles 6, parser 5 (same json load)
- Docs agree on 102: README.md:132, docs/guides/ai-assessment.md:9, docs/guides/model-development.md:112
- Marker scan (TODO, FIXME, stub, placeholder, unimplemented, deprecated) over the slice: no matches (`rg -i`)
- Doctor: no FAIL lines (`clean-development doctor`)

3. broken
- Drift check fails on the system Python: `ModuleNotFoundError: No module named 'requests'` via src/azure_tenant_audit/graph.py:10 (`python3 -I scripts/generate-rule-packs.py --check`). Not installed; out of scope.
- Importing azure_tenant_audit.value_rules fails for the same reason (src/azure_tenant_audit/__init__.py:3). A project venv is needed.

4. dead candidates
- none confirmed; live but low name-reference counts: value_rules/aad_authz.py (0 name imports; kinds authz and priv_users used by 6 policies), value_rules/exo_open.py (1 reference; exo_forwarding used by 1 policy). Both are reached by registry discovery (value_rules/__init__.py:_registry).
- tests/fixtures/value-rules/held-rows-s4.json and held-rows-s5.json: no longer a gate, still read by scripts/build-value-rule-fixture-s5.py. Not dead.

5. contradictions
- value_rules/defender_spam.py:6 says the kinds are "held until P4 lands"; the config has spam_cascade rows for MS.SECURITYSUITE.6.1v1 and 6.2v1, and tests/fixtures/value-rules/held-rows-README.md says they are enabled. Stale docstring.

6. open questions
- Does the drift check pass in a venv with deps? Run `.venv/bin/python scripts/generate-rule-packs.py --check`. Not run here.
- Are all 25 `not_assessed` lines in value_rules/ legitimate verdict branches? Settle with tests/test_value_rules_contract.py. Not run (no test suites in this slice).
- Is rule_not_implemented unreachable for the 102 policies? Makefile:90 asserts zero such rows; settle by running that target.
- Neighbour (one line): configs/scuba-rule-precheck.json and configs/scuba-scope-blind.json sit beside the value-rule config; out of slice.
- Neighbour (one line): the SessionStart hook reported a clean-development lifecycle registration/cleanup failure. `clean-development doctor` shows no FAIL and no lifecycle line, so the hook's failure is not reproduced by doctor. Its warnings: stray ~/dev entries, unexpected dot-folders, and six repos without `.clean-development.json` (infra, pentest-local, pentest-local-public-staging, wattex, wgex, wgex-plan). Auditex is not on those lists. G may want `clean-development doctor` run from an interactive shell to confirm the registration.
