## RESULT INV3-lint
status: done
summary: Ruff is configured in pyproject.toml:57 (E4, E7, E9, F) and enforced by a pre-commit ruff-check hook at v0.17.0. Pinned ruff 0.17.0 reports 230 findings, led by E701 (99) and F811 (42). The tests directory holds 196 of them and src holds 34. Full detail is in .plan/work/INV3-lint/notes.md.
changes: none in the repo; notes written to .plan/work/INV3-lint/notes.md
verification: uvx ruff==0.17.0 check . --no-cache --statistics: 230 errors, pass as a probe (exit non-zero by design). Broader E,F,W,I,B,UP probe: 31,811 errors, probe only. make lint and tests not run.
risks: The broader rule set is about 31k findings, so a repo-wide switch is not cheap. The pre-commit hook will fail any commit touching the 54 flagged files until they are fixed or noqa'd (inferred). The ruff binary is not in the main .venv.
questions_for_g: Which rule set and target-version should the repo adopt, and should F811 in tests/test_key_guard_*.py be fixed or suppressed?
### Findings
1. exists
- pyproject.toml:57 `[tool.ruff.lint] select = ["E4","E7","E9","F"]`; pyproject.toml:60-62 per-file-ignores for tenant-bootstrap/scripts/seed-workload-az.py (F811); file exists.
- .pre-commit-config.yaml: astral-sh/ruff-pre-commit v0.17.0, hook ruff-check only; no ruff-format hook.
- Makefile:19-20 `lint` = compileall of src and tests.
- .github/CONTRIBUTING.md:27,33,35: make lint is compile-only; pre-commit install recommended.
- 595 Python files: tests 312, src 211, tenant-bootstrap 45, scripts 26, benchmarks 1.
2. works
- `uvx --from ruff==0.17.0 ruff check . --no-cache --statistics`: 230 errors in 54 files; 40 fixable.
- `ruff --output-format concise` aggregated by top dir: tests 196, src 34, others 0.
- `rg --files -g '*.py'` per top dir: counts as above.
- `ls .github/workflows`: missing (no CI workflow found).
- `.venv/bin/ruff` in main checkout: absent (ls); `command -v ruff`: empty.
3. broken
- none (no failing command. Ruff findings are lint results, not command failures.)
- Mention: 230 existing findings would fail the pre-commit ruff-check on any touched file (inferred from config).
4. dead candidates
- none found. Not in scope for this slice (no dead-code scan run).
5. contradictions
- none found: AGENTS.md "make lint is compileall only" matches Makefile:19-20 and CONTRIBUTING.md:33.
6. open questions
- Is the ruff hook installed in the main checkout? Settle with `pre-commit run ruff-check --files <file>` in a writable checkout (.git/hooks not read).
- Does `make lint` pass today? Not run (compileall writes .pyc into the worktree). Settle in a writable checkout.
- Are the F811 redefinitions in tests/test_key_guard_stdin.py:43 (and siblings) intentional? Settle by reading tests/test_key_guard_stdin.py:1-45.
- Broader probe (E,F,W,I,B,UP): 31,811 errors, mostly UP017 (84), B905 (72), UP035 (63). Likely driven by default target-version (inferred). Needs a target-version and rule-set decision.
- Neighbour area: AGENTS.md says release-check runs lint; its definition lives in Makefile, not read here.
