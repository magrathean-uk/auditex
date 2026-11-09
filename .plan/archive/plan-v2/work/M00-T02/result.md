## RESULT M00-T02
status: partial
summary: Review item 1 fixed: dist builds and checks a wheel and sdist in separate processes.
summary: Review item 2 answered here; the earlier partial result remains unchanged.
summary: Archive extraction, safe unset-TMPDIR default, ignored dist directory and release-check order were already in place. The existing Python selector prefers .venv when present.
summary: Both artefacts were produced with TMPDIR unset; set-TMPDIR verification remains blocked.
changes:
- Makefile
verification:
- `PYTHON_BIN=<4TB>/machine/cache/venvs/auditex/bin/python env -u TMPDIR make release-archive dist && PYTHON_BIN=<4TB>/machine/cache/venvs/auditex/bin/python make release-archive dist && git check-ignore -q dist/x` - failed: sandbox denied mktemp in the routed TMPDIR during the second make; the final ignore check did not run.
- `ls dist/*.whl dist/*.tar.gz` - passed.
- `make release-check` - skipped: process listing failed, so the required heavy-job load check could not be completed.
- `git status --porcelain` - passed; only Makefile changed.
- `clean-development doctor` - failed: GUI environment and Xcode DerivedData routing mismatch; lifecycle lock requires explicit recovery.
risks:
- Acceptance verification and the full release gate still need a permitted environment.
questions_for_g: none
dispatch: committed 836261c on task/M00-T02-tmpdir-safe-make (1 paths: Makefile)
