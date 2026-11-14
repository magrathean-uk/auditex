## RESULT REV-M08-T08
status: done
summary:
verdict: approve
reviewed: 4fb66bd5a28765ce972a4f7f2fdbbbdc69fb2c51
Required repair and prior defect classes are fixed by inspection. No blocking findings.
changes: none
verification: not runnable: `.venv/bin/python -m pytest tests/test_first_collection_graph_fixes.py tests/test_auth_methods_collector.py tests/test_scuba_adapters_aad.py tests/test_scuba_projection.py tests/test_external_sharing.py tests/test_collection_gaps.py && make contract-smoke`; exit 127, first error: `zsh:1: no such file or directory: .venv/bin/python`. Sandbox prevents creating the interpreter link. `git diff --check 8319adb4b51fb009db21f22499042f11fe15d8ec..HEAD` passed.
risks: Tests and contract smoke remain unexecuted here; progress notes could not be written in the read-only sandbox.
questions_for_g: none
### Findings
- D1 inline read and null migration state: met by inspection, `src/azure_tenant_audit/collectors/auth_methods.py:21`, `src/auditex/scuba_adapters_aad.py:47`.
- D1 deciding fixture: met by inspection, `tests/test_first_collection_graph_fixes.py:109`; AAD 3.3/3.5 decide and 3.4 remains not assessed.
- D3 unrelated fan-out attribution: met by inspection, `src/auditex/scuba_projection.py:307`, `tests/test_first_collection_graph_fixes.py:140`.
- D3 relevant truncation and AAD 5.2: met by inspection, `tests/test_first_collection_graph_fixes.py:151`; usable evidence decides before truncation and is withheld afterwards.
- D7 no app-only permission read and named skip: met by inspection, `src/azure_tenant_audit/collectors/sharepoint_access.py:142`. Delegated behaviour retained, `tests/test_first_collection_graph_fixes.py:224`.
- Evidence safety: met by inspection, `src/azure_tenant_audit/baselines.py:1086`; all four permission-dependent checks are guarded, with the external-principal domain requirement retained at line 1090.
- Changelog hand-off: met, `.plan/work/M08-T08/changelog.md:1` in the main checkout; no CHANGELOG or permission-doc change in this repair.
- Scope: `src/azure_tenant_audit/baselines.py` is outside the milestone files line but explicitly authorised by `.plan/work/M08-T08/brief.md:7`. `tests/test_first_collection_graph_fixes.py` is listed. No unexplained scope.
- DoD: M08-T08's static portion of `.plan/milestones/M08-collection-completeness.md:38` is met by inspection. Executable verification is untestable; merge binding at line 33 and milestone-wide checks at line 40 remain orchestrator gates. Phase-D and M08-T11 closure remain dependent work.
- Security/maintainability: no new secrets, injection surfaces, unsafe deserialisation, dependencies, file-mode changes, dangling renamed references or architecture violations found. Regression asserts all four withheld outcomes and delegated passes.
- Required changes: none.
### Prior review re-check
- Result-2 required change 1: fixed, `src/azure_tenant_audit/baselines.py:817`, `tests/test_first_collection_graph_fixes.py:252`; known tenant domains and completed domain collection expose the previously missed false passes.
- Inherited required change 1: fixed, `src/azure_tenant_audit/baselines.py:1086`.
- Inherited required change 2: fixed, `tests/test_first_collection_graph_fixes.py:109`, `tests/test_first_collection_graph_fixes.py:118`.
- Inherited required change 3: fixed, `tests/test_first_collection_graph_fixes.py:151`, `tests/test_first_collection_graph_fixes.py:167`, `tests/test_first_collection_graph_fixes.py:178`.
- Defect class "Skipped evidence promoted to complete coverage and false passes": fixed, `src/azure_tenant_audit/baselines.py:1086`, `tests/test_first_collection_graph_fixes.py:265`.
- Defect class "Acceptance tests stop before required rule verdicts": fixed, `tests/test_first_collection_graph_fixes.py:112`.
- Defect class "Negative tests pass because their requested artefacts are absent": fixed, `tests/test_first_collection_graph_fixes.py:163`, `tests/test_first_collection_graph_fixes.py:175`, `tests/test_first_collection_graph_fixes.py:188`.
