## RESULT M00-T02
status: partial
summary: Removed the pytest override and changed the taint scan to use tracked files; verification stopped at a sandbox-denied cache write.
summary: The review instruction to use the criteria command and Makefile targets was followed; the remaining targets were not run after the denial.
changes: pytest.ini; scripts/oss-taint-scan.sh
verification: Baseline pytest collection passed. The criteria command failed at `make audit-deps`: uv could not create a temporary file in `~/dev/machine/cache/deps/uv` (operation not permitted). Subsequent scan and collection checks, `make lint`, `make test` and `make release-check` were skipped.
risks: Before-and-after collection counts and scan behaviour remain unverified; required result.md evidence was not written.
questions_for_g: none
dispatch: committed dad12f3 on task/M00-T02-test-hygiene (2 paths: pytest.ini, scripts/oss-taint-scan.sh)

### Evidence (filed by the orchestrator from the REV-M00-T02 run at dad12f3)
Verify command, run in the review worktree with .venv linked:
- `! grep -q '!Review' pytest.ini`: pass
- `! grep -q 'docs/taint' scripts/oss-taint-scan.sh`: pass
- `make audit-deps`: pass (rc 0, "No known vulnerabilities found" for every set; build/audit-deps filled)
- `bash scripts/oss-taint-scan.sh` after audit-deps: pass ("oss-taint-scan: clean", rc 0)
- `.venv/bin/python -m pytest --collect-only -q`: pass (rc 0)

Collection before (`-o norecursedirs='!Review'`) vs after (default): 286 files, 24067 ids each, per-file counts identical.
Tracked files scanned: 1071 tracked, 1037 after the exclusions; pathspec exclusions (provenance, microsoft-skills, the script itself, third-party-notices.md at any depth, *.pyc) all match tracked files.
Removed prunes: .git, .venv, .secrets, outputs, .pytest_cache, docs/taint (absent), __pycache__ (all untracked or ignored, so not listed by git ls-files).
Worktree stayed clean (git status empty).
