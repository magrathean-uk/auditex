## RESULT M01-T05
status: done
summary: `security-privacy.md` now lists the seven MCP tools whose `read_only_hint` is false, each with its reason. It replaces "Read-only annotations are unchanged".
summary: The credential wording in the doc and the `McpToolEntry` docstring now says Google tools take confined paths to credential files (`service_account_key`, `oauth_client`, `token_cache`), not secret values. The registry matches this, so no gap to report.
summary: A new test in `tests/test_mcp_registry.py` checks the doc's list equals the registry's non-read-only set, with response tools included.
changes: docs/reference/security-privacy.md, src/auditex/mcp_registry.py (docstring only), tests/test_mcp_registry.py (commit 1e25c95 on task/M01-T05-mcp-privacy-docs)
verification: `pytest tests/test_mcp_registry.py tests/test_mcp_paths.py` with `PYTHONPATH=src` and the main checkout's `.venv` interpreter, pass. `git status --porcelain` is empty.
risks: The worktree has no `.venv`, so I ran with the main checkout's interpreter.
risks: The test finds the doc list by splitting on blank lines, so it breaks if the section's layout changes.
questions_for_g: none
