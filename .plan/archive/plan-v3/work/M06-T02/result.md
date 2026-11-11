## RESULT M06-T02
status: done
summary: All six gates passed on commit 5843f0b4977c410f484502d424b6151d54d7be94 (version 1.4.0). Both builds were byte-identical to each other and to the step d artefacts. The first release-check attempt was killed by the harness 10-minute limit (not a test failure); the rerun under a fresh OUT passed. Heavy-job rule: load was 13.04 at start, so I waited until it was 10.80 before running anything.
changes: none (only the git-ignored `.venv` link, `dist/`, `build/`)
verification:
- a. `make release-check`: exit 0. pytest 22620 passed, 273 skipped, 0 failed, 7 deselected, 34 xfailed. Rule-pack drift check, taint scan and gitleaks were clean.
- b. `make audit-deps`: exit 0, no known vulnerabilities.
- c. `make acceptance` with v3.9.1 vectors: exit 0. Value-rule replay passed with 26901 vectors and no skip entries in the tally. Explainer mutation chunks 00-03 each passed, 2 harmful cases undetected in chunk 0 and 2 in chunk 1 (the suite passes them). Twins and byte-identical suites passed, with the same output digest on both runs (31492cbe...fc0bc).
- d. `make dist`: exit 0.
  - wheel `dist/auditex-1.4.0-py3-none-any.whl`: sha256 cd66fe86c9723031f3d114e02c89faeb3eeb81480739780aa9bd87d9639b0497
  - sdist `dist/auditex-1.4.0.tar.gz`: sha256 d41f154a116cf006839ac87d6dfb889f830ef4002258d03596106e33c7272554
- e. `bash scripts/release-smoke.sh dist ...`: exit 0, "release smoke ok".
- f. `scripts/check-reproducible-build.py`: exit 0, "reproducible build ok". Both builds were byte-identical, with wheel and sdist hashes equal to step d.
risks: none
questions_for_g: none
