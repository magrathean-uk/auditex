## RESULT M01-T03
status: done
summary: Review item fixed: the static allow-list test the previous attempt left out is now implemented, along with every other criterion.
- Static AST scan of src/ (requests, Session verbs, request/_request wrappers, urllib Request/urlopen/opener, Graph $batch, msal and google-auth token calls); any non-GET site must match the frozen section E allow-list (class, row, reason, exact count); new or extra sites and stale entries fail. Criterion met.
- Variable-method sites resolved to guards: Graph _request must start with _enforce_read_only, which calls read_only_violation; Power Platform A8/A9 resolve to ALLOWED_METHODS == {"GET"}. Criterion met.
- Runtime: the Graph guard refuses non-GET requests and a $batch with a non-GET sub-request on both roots, with nothing sent. Criterion met. The graph.py comment names GET, the GET-only redirect hops, POST to /v1.0 and /beta $batch, and the class 2 token POSTs outside the guard. Criterion met.
changes: tests/test_http_verb_allowlist.py (new, c006fbf); tests/test_read_guard.py (bbefa73); src/azure_tenant_audit/graph.py (comment only, ff059cf)
verification: `.venv/bin/python -m pytest tests/test_http_verb_allowlist.py tests/test_read_guard.py tests/test_graph_read_only.py tests/test_transport_hygiene.py` pass (331 passed) on head ff059cf; module `.venv/bin/python -m pytest tests/test_read_guard.py tests/test_graph_read_only.py tests/test_contract.py` pass (276 passed) and `make contract-smoke` pass; git status --porcelain empty
risks: The static scan misses verb methods reached through an alias or getattr, and Session.send with a prepared request (noted in .plan/work/M01-T03/notes.md).
- googleapiclient chained calls such as users().delete().execute() are out of scope here; the Google read boundary is M01-T04.
- The worktree .venv is a git-ignored symlink to the shared venv at <4TB>/machine/cache/venvs/auditex.
questions_for_g: none
