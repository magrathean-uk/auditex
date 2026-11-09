## RESULT M02-T04
status: done
summary: The runbook check table now lists `release-archive`, `make dist`, `make audit-deps`, the wheel and sdist smoke and `check-reproducible-build.py`, and `release-check` includes `release-archive`. The release paragraph uses `make dist`. A new Publication section states the DEC-001 publication (signed `v1.3.0` tag plus a GitHub release with wheel and sdist, no PyPI) and says it waits for G's yes naming the version. A new Internal tools section links `scubagear-export-adapter.md` as internal and experimental.
changes: docs/development/runbook.md
verification: The criteria's grep over `docs/development/runbook.md` returned a match for all six terms (pass). `git status --porcelain` is empty after the commit. No tests were run, because the change is docs only.
risks: The `gh release create` command shown in the runbook is not run or checked. It names the artefact globs as `dist/*.whl dist/*.tar.gz`.
questions_for_g: none
