## RESULT M01-T07
status: done
summary: Rebased task/M01-T07-gmail-fields-masks onto main. The only conflict was in tests/test_read_boundaries.py, in three hunks, and I kept both sides' rows. The Gmail fields-mask rows (G1, G2, G5) use the disposition "removed at request level". The transport-rule rows (G6, from main) use "removed_at_request". The disposition-header comment and the allowed-set assertion now list both strings. I changed nothing else. The branch is clean and its head is the rebased commit.
changes: tests/test_read_boundaries.py (conflict resolution only). The rebased commits also carry docs/reference/output-contract.md, src/auditex/google_workspace/client.py, src/azure_tenant_audit/data_minimisation.py, tests/test_collection_coverage_fixes.py, tests/test_data_minimisation.py and tests/test_google_workspace.py.
verification: `.venv/bin/python -m pytest tests/test_read_boundaries.py tests/test_google_workspace.py tests/test_google_collection_gaps.py tests/test_data_minimisation.py tests/test_google_parity.py -q` passed after the rebase. `git status --porcelain` is empty.
risks: The two disposition spellings ("removed at request level" and "removed_at_request") now sit side by side in the table. Merging them into one is a tidy-up for a later task, and I left it alone.
questions_for_g: none
