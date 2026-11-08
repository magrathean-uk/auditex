## RESULT M00-T05
status: done
summary: Fixed review item 1 by updating the smoke matrix test to the `${artifact}` forms and adding wheel/sdist loop assertions. Item 2 is done: the smoke script ran green for wheel and sdist, base, google and mcp. The reproducible-build check also passed. I also made the `TMPDIR` fallback in the check script (a non-blocking suggestion).
changes: tests/test_architecture_modules.py, scripts/check-reproducible-build.py (commit 00afb73; earlier commit 1d80d94 covers the rest)
verification:
- `pytest tests/test_check_reproducible_build.py tests/test_architecture_modules.py`: pass (36 passed)
- `make dist PYTHON=<main venv python>`: pass. The worktree has no `.venv`, so the default `make dist` fails with "No module named setuptools".
- `PATH=<main venv bin>:$PATH bash scripts/release-smoke.sh dist "$TMPDIR/auditex-release-smoke"`: pass, "release smoke ok"
- `<main venv python> scripts/check-reproducible-build.py`: pass, "reproducible build ok"
- `git status --porcelain`: empty
risks:
- The smoke script needs `python` on PATH, and this worktree has no `.venv`, so the verify command only works where the venv is active.
- The remaining non-blocking suggestions are not done: the runbook `/tmp` path, `extractall(filter='data')` needing Python 3.11.4 or later, the unindented loop body, and wheel-comparison test coverage. The runbook sits outside my files.
- Each smoke run leaves a `run.XXXXXX` directory under `$TMPDIR`.
questions_for_g: none
