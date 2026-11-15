## RESULT M08-FIX2
status: done
summary: The allow-list entry for the $batch POST now sits on GraphClient._post_batch instead of get_batch, with the same transport class and reason. _post_batch is the only new non-GET site. Its only caller is _run_batch_chunk, which gets its items only from get_batch: get_batch refuses non-GET specs, and _request checks the inner requests again through the read guard. The _request docstring is now a comment, so _enforce_read_only is its first statement again. The negative fixture is renamed from get_batch to _post_batch so it still tests the entry; the test's rules are unchanged. Commit 7b252dd on task/M08-FIX2-verb-allowlist.
changes: src/azure_tenant_audit/graph.py, tests/test_http_verb_allowlist.py
verification: pytest on tests/test_http_verb_allowlist.py, test_graph_batch_retry.py, test_graph.py and test_graph_read_only.py pass (241 passed); make lint pass; gitleaks on the staged changes found no leaks
risks: Tier A network guard, so it needs a review by the other provider before merge. Full make test was not run, because the brief only asked for the focused tests.
questions_for_g: none
### Findings
fix: tests/test_http_verb_allowlist.py:180
fix: tests/test_http_verb_allowlist.py:1095
fix: src/azure_tenant_audit/graph.py:688
tests: pass 241 passed 0 failed
lint: pass
