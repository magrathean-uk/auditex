## RESULT M06-T02
status: done
summary: All seven steps exited 0 on candidate a1c6b5e, run through the heavy slot with the replay kit set. Two plain builds gave identical wheel and sdist bytes. Step 1 failed on its first attempt only because the new worktree had no `.venv`, so one test could not find `.venv/bin/auditex`. I linked the main checkout's `.venv` into the worktree as a git-ignored symlink (the run rules allow this) and step 1 then passed. The worktree is clean at the candidate.
changes: none (the candidate worktree gained only the git-ignored `.venv` symlink and `dist/`, `outputs/`, `build/`)
verification: steps 1 to 7 pass; `git status --porcelain` is empty and `HEAD` equals the candidate. Logs are in `.plan/work/M06-T02/logs/`, and the failed first attempt is kept as `1-release-check.attempt1-no-venv-link.log`.
risks: the first step 1 attempt failed (1 failed, 23130 passed) until the `.venv` symlink was added, and it reached the one test that spawns `.venv/bin/auditex`, which the candidate binding does not mention; the later release steps (M06-T04 onward) should expect to link it too. The first step 1 attempt, and a second one launched with a 10-minute limit, were cut off by my own launcher; these were launcher stops, not test failures.
questions_for_g: none
### Findings
candidate: a1c6b5e6e54e1fcc8fb224868a7e8467c723d262
wheel-sha256: 81ea5c2f00bca2d0a880f4fe2527a7a917329396aaaba207c1da00f6ce444eba
sdist-sha256: 959e825f2bcd769222789c1b5fc3fff8f2acbfc955ba6c9473c6807563b6ee1a
step 1 release-check: exit 0 (full suite 23131 passed, 254 skipped, 7 deselected, 34 xfailed; Ruff, rule-pack drift, taint scan and gitleaks clean)
step 2 audit-deps: exit 0 (no known vulnerabilities in any requirement set)
step 3 contract-smoke: exit 0; digest comparison: all 43 digests match
step 4 acceptance: exit 0 (replay 1 passed, 0 skipped over 26,901 vectors; value-rules contract 192 passed; explainer mutation chunks 4 x 1 passed; twins 1 passed; byte-identical 1 passed)
step 5 dist: exit 0 (exactly one wheel and one sdist in dist/)
step 6 release-smoke: exit 0 (base, Google and MCP; "release smoke ok")
step 7 reproducible build: exit 0 (first and second builds identical for wheel and sdist)
worktree: `$CLEAN_DEV_WORK/worktrees/auditex/v4-M06-candidate`, clean, HEAD equals the candidate
