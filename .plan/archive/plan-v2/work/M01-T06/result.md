## RESULT M01-T06
status: done
summary: All three files in examples/model_development/ are classified. cases.jsonl has 48 rows (train 32, validation 8, test 8; 12 families, none shared across splits). Both fixtures have 48 rows whose case_ids all join to cases.jsonl. No row is held-out, sealed, real or derived from a held-out set.
changes: none to the repo; notes written to .plan/work/M01-T06/notes.md
verification: git diff --quiet -- examples/model_development (pass); python3 -I JSON parse and join checks (pass, 0 bad rows); scripts/build-model-examples.py --check (fail: ModuleNotFoundError requests, src/azure_tenant_audit/graph.py:10, not installed)
risks: The held-out comparison is inferred from the generator, not proven against the holdout id list. The --check result is unverified. The plan's verify command expects .plan/work/M01-T06/result.md, which does not exist.
questions_for_g: none
### Findings
1. exists
- examples/model_development/cases.jsonl (48 rows); fixture-model-a.jsonl and fixture-model-b.jsonl (48 rows each)
- scripts/build-model-examples.py (generator, header :1-5)
- tests/test_model_cli.py:13,115-185 consume them
- docs/guides/model-development.md:36-40, 73-84
- docs/provenance/provenance.csv:24
- pyproject.toml:85; src/azure_tenant_audit/shipped_content.py:96-100
2. works
- git diff --quiet -- examples/model_development: clean
- python3 -I parse of all three files: 48 rows each, 0 bad JSON, unique case ids
- cases.jsonl split: train 32, validation 8, test 8; families 8/2/2, none shared across splits
- cases.jsonl provenance on all 48 rows: source auditex-synthetic-generator-v3, synthetic true, review_status unreviewed (generator :61)
- fixtures: model_id matches file name on 48/48 rows; case_id joins to cases.jsonl 48/48. Fixtures have no split or provenance field.
- expected claims: confirmed 70, unknown 46
- docs/guides/model-development.md:36-40 counts match
3. broken
- scripts/build-model-examples.py --check: ModuleNotFoundError requests (src/azure_tenant_audit/graph.py:10). Environmental; not run further per brief.
- .plan/milestones/M01-boundary-proof.md:76 verify path .plan/work/M01-T06/result.md missing (not created; brief names notes only)
4. dead candidates
- none. Both fixtures are referenced by tests/test_model_cli.py and the guide.
5. contradictions
- none found within the slice. The `eval` hits (conditional-access-mode-01..04) are the value not_evaluated, not evaluation rows.
6. open questions
- Does the generator --check pass in the project venv? Run .venv/bin/python scripts/build-model-examples.py --check after make install.
- Do any case ids or families match the frozen holdout ids? Compare against the holdout id list (docs/guides/model-development.md:655 test_ids_sha256; list outside this slice).
- Should result.md be created to satisfy the plan's verify line? Plan owner to settle.
- Neighbouring area: docs/provenance/provenance.csv:47 and docs/guides/model-development.md:511,655,674 cover the holdout and value-rule vectors, not this slice.
