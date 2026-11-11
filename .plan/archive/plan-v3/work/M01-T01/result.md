## RESULT M01-T01
status: done
summary: Plain `make dist` now pins `SOURCE_DATE_EPOCH` to the `HEAD` commit time when unset and normalises the sdist (gzip header time, member times, owner, group, mode, order). `scripts/check-reproducible-build.py` runs plain `make dist` twice in separate clones of `HEAD` and compares wheel bytes and sdist bytes. It names any differing artefact and exits 1. All four criteria are met. The runbook states the byte-identity guarantee.
changes: Makefile, scripts/check-reproducible-build.py, tests/test_check_reproducible_build.py, docs/development/runbook.md (one commit)
verification: pytest tests/test_check_reproducible_build.py pass (5 tests, including identical members with different gzip headers reported as different); check-reproducible-build.py pass (wheel and sdist hashes identical across both builds); make release-archive pass; make dist then release-smoke.sh pass ("release smoke ok"); `git status --porcelain` empty
risks: gzip bytes depend on the zlib build, so identity is guaranteed per toolchain, not across machines; the normaliser lives in the check script (`--normalise-sdist`) because the brief allows no new files; the check needs `make` and a local clone of `HEAD`, so it ignores uncommitted changes
questions_for_g: none
