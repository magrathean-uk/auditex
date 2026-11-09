## RESULT M00-T07
status: done
summary: `scripts/release-smoke.sh` now picks its interpreter from `PYTHON`, else `.venv/bin/python` in the repo, else `python3`. Each smoke venv is built with that interpreter, and every later call uses that venv's own `bin/python`, so no bare `python` is left. The smoke passed for wheel and sdist across base, google and mcp with `PATH=/usr/bin:/bin`. The architecture test file needed no edits.
changes: scripts/release-smoke.sh (commit e1f8dc4)
verification: `make dist` pass; `env PATH="/usr/bin:/bin" bash scripts/release-smoke.sh dist "$TMPDIR/auditex-release-smoke"` pass (exit 0); `.venv/bin/python -m pytest tests/test_architecture_modules.py` pass (35 tests); `git status --porcelain` empty
risks: The worktree's git-ignored `.venv` is a link to the main checkout's venv. The smoke's `auditex` calls still rely on venv activation, which is unchanged.
questions_for_g: none
