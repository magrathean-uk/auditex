## RESULT M00-T05
status: partial
summary: Extended the smoke script to cover wheel and sdist installs for base, google and mcp.
summary: Added a two-build comparison and a focused sdist-member test; the acceptance criteria remain unverified.
summary: Clean Development doctor failed: lifecycle lock owner unverifiable, GUI environment unset and DerivedData routing mismatched.
changes:
- scripts/release-smoke.sh
- scripts/check-reproducible-build.py
- tests/test_check_reproducible_build.py
verification:
- `make dist && bash scripts/release-smoke.sh dist "$TMPDIR/auditex-release-smoke" && .venv/bin/python scripts/check-reproducible-build.py` - failed at `make dist`: sandbox denied creation under the routed `$TMPDIR`.
- `python3 -B -m pytest tests/test_check_reproducible_build.py` - failed: pytest unavailable; `.venv` is absent.
- `bash -n scripts/release-smoke.sh` and Python source compilation - passed.
- `make release-check` - skipped: required environment is absent and the heavy-job process check was unavailable.
- `git status --porcelain` - passed: only the three owned paths are changed.
risks: Build reproducibility and all six installation smoke checks have not been executed.
questions_for_g: none
dispatch: committed 1d80d94 on task/M00-T05-sdist-repro (3 paths: scripts/release-smoke.sh, scripts/check-reproducible-build.py, tests/test_check_reproducible_build.py)
