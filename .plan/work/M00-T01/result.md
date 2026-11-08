## RESULT M00-T01
status: partial
summary: make release-check ran on 0a73759 (main head, precondition met) and failed at make test on one test. Lint passed (make only advances past a passing step); contract-smoke, release-archive, rule-pack drift, taint scan and gitleaks were not reached.
changes: none (repo); notes at .plan/work/M00-T01/notes.md; run log at .plan/work/M00-T01/gate-1-release-check/log.txt
verification: `uptime` load 5.72 (1-min) and 10.05 (5-min) on 12 cores, pass; heavy-job pgrep, none; `make release-check`, FAIL after 2084.66 s; pytest 1 failed, 23183 passed, 321 skipped, 7 deselected, 34 xfailed (log.txt:421); `make audit-deps`, `make dist`, `scripts/release-smoke.sh`, `scripts/check-reproducible-build.py`, not run (stopped at first failure per acceptance)
risks: The failing test may hide a wheel-packaging defect for 1.3.0. Pre-run load was fine but the 5-minute load reached 13.85 after the run, above the core count.
questions_for_g: Reading of the brief: its "no full test suites" constraint conflicts with the gate run it asks for. I ran the gates, since the acceptance criteria require them. Confirm that is what you wanted. Clean-development: the SessionStart hook reported a lifecycle registration/cleanup failure and asked for `clean-development doctor`. I did not run it, per the brief. Do you want it run?
### Findings
1. exists
- Makefile:48-49 AUDIT_DEPS_DIR and AUDIT_DEPS_IGNORE. Makefile:56-75 audit-deps. Makefile:77-85 release-check. Makefile:87-101 release-archive. Makefile:103-118 dist.
- .clean-development.json:6-9 buildDirs build and dist. .gitignore:9 dist/. pyproject.toml:46-49 pip-audit in the dev extra.
- scripts/release-smoke.sh, scripts/check-reproducible-build.py, scripts/check-archive-wheel.py, scripts/oss-taint-scan.sh, tests/test_check_reproducible_build.py: present (Glob).
- Merged per main log: bb50c0a (T02), b702d8a (T03), f0ae2a7 (T05).
2. works
- Load rule and heavy-job check: `uptime`, `pgrep -lx 'xcodebuild|cargo|tart|colima|limactl'`, `pgrep -fl 'swift-(build|test|frontend)'`. Pass.
- Lint: passed before test (make ordering; Makefile:79-80).
- Worktree HEAD equals main (0a73759): `git rev-parse`.
3. broken
- make test fails: tests/test_explainer_integration.py::test_installed_wheel_resources_offline (log.txt:420), assertion at tests/test_explainer_integration.py:159. The subprocess returns non-zero; its stderr is not in the log (log.txt:409-416).
- Gates 2-5 not run.
4. dead candidates
- none. scripts/audit-deps-ignore.json is absent, but Makefile:69 handles a missing file, so it is not a defect.
5. contradictions
- Makefile:55 and the audit-deps rule require DECISIONS.md ids for ignore entries; no DECISIONS.md exists in the tree (Glob). docs/development/runbook.md:110 cites DEC-001. Inferred: the decision log lives elsewhere or is missing.
6. open questions
- Cause of the test failure: rerun that test on 0a73759 and capture the subprocess stderr (tests/test_explainer_integration.py ~150-159); compare with 726feed to see whether it is new.
- Location of DEC-001 and DECISIONS.md: `rg -n 'DEC-001'` over the main checkout, excluding .venv.
- Neighbour: explainer resource packaging (azure_tenant_audit resources and explainer) is the failing area, outside M00-T01's own files.
