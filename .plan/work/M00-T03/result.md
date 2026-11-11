## RESULT M00-T03
status: done
summary: AGENTS.md now describes `make lint` as compileall plus the pinned Ruff check (E4, E7, E9, F, W, I, B, UP). It also has one line each for `make acceptance` and `make dist`. The runbook's publication paragraph describes the release form (signed tag, GitHub release with wheel and sdist, no PyPI, G's yes naming the version) with `vX.Y.Z` placeholders instead of 1.3.0. Nothing else changed. Committed as fe1c6d7; worktree clean.
changes: AGENTS.md, docs/development/runbook.md
verification: the criteria verify line (grep checks) - pass on the committed head
risks: none
questions_for_g: none
