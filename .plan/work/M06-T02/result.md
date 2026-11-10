## RESULT M06-T02
status: done
summary: All six gates (a to f) exited 0 on the release candidate. Load was 16.3 at start and dropped to 10.9 within about 10 minutes. Nothing else heavy was running.
changes: none (git-ignored dist/ and build/ output only; `.venv` symlink is git-ignored)
verification: a. make release-check pass (exit 0); b. make audit-deps pass (exit 0, no known vulnerabilities in any requirements file); c. make acceptance with the v3.9.1 vectors pass (exit 0); d. make dist pass (exit 0); e. release-smoke.sh pass (exit 0, "release smoke ok"); f. check-reproducible-build.py pass (exit 0, "reproducible build ok")
risks: none
questions_for_g: none

### Findings
- commit: 0589f0798f90c5a2010bf83c9d3616ae5a284f0a
- release-check pytest: 22617 passed, 273 skipped, 7 deselected, 34 xfailed, 0 failed. The ruff lint, the oss-taint-scan and gitleaks (no leaks) also passed.
- acceptance, replay: `tests/test_value_rules_replay.py` passed with the v3.9.1 vectors. The replay tally had 26901 vectors, 19118 where the rule equalled gold, 13194 where the response equalled gold, and 190 A2 overrides applied. It reported no skip keys and a pytest skipped count of 0.
- acceptance, explainer suites: the mutation suite and the integration suites each passed, 1 passed with 0 skipped per suite.
- wheel (`auditex-1.4.0-py3-none-any.whl`): sha256 b44935f7315e11359d108a3282a9596b2b0a0f90cd79be760e87cd6d5d38b38a
- sdist (`auditex-1.4.0.tar.gz`): sha256 d1c36aaf1934ccc9ec4395e85601aa9ee356e79ba4d3300fbcac64ea98540e46
- reproducible build: both clone builds are byte-identical and carry the same wheel and sdist hashes as step d.
