## RESULT M08-FIX1
status: done
summary: Rebased onto main (adds M08-T09) with no conflicts, then amended the one commit. Inserted remainingseconds, retryexhausted, waitedseconds and waitseconds into `_D5_FIELD_NAMES` in alphabetical order, wrapped the same way as round 1. The failure-list files, tests/test_graph_batch_retry.py and make lint all pass on the final head. .venv link removed after.
changes: src/azure_tenant_audit/output_redaction.py
verification: pytest on the 8 failure-list files plus tests/test_graph_batch_retry.py pass (1243 passed, 7 deselected); make lint pass
risks: none
questions_for_g: none
### Findings
rebased-onto: be74c0440bb0
head: b3a10137bf54
fix: src/azure_tenant_audit/output_redaction.py:2651 (also 2669, 2786)
tests: pass 1243 passed, 7 deselected
lint: pass
