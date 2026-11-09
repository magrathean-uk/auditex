## RESULT M00-T03
status: done
summary: Gate run on main at e6531a3. lint, contract-smoke and audit-deps exit 0. release-check exit 2 with 1 failed test, so main is red. Make stopped at the test target, so steps after it did not run.
changes: none tracked. Added a git-ignored `.venv` symlink to the main checkout's venv in the worktree.
verification:
- make lint: pass (exit 0)
- make release-check: FAIL (exit 2). pytest: 1 failed, 23679 passed, 319 skipped, 34 xfailed, 7 deselected (1014.57s).
- Failing test: tests/test_parser_error_privacy.py::test_no_parser_constructor_or_subparser_override_outside_factory (line 652). First failing line: `E AssertionError: assert not [('scripts/compare-run-outputs.py', 229)]`
- make contract-smoke: pass (exit 0). Bundle seal verified, 102 value-rule rows, 0 not assessed.
- make audit-deps: pass (exit 0)
- Logs: under $TMPDIR/m00t03/ (lint.log, release-check.log, contract-smoke.log, audit-deps.log, status.txt)
risks:
- The first release-check run was stopped by the harness at about 65% (background time limit). The reported run is a full single rerun.
- A SessionStart hook reported clean-development lifecycle registration failure and asked for `clean-development doctor`. I did not run it, because this brief forbids it without explicit authorisation. G to decide.
- Host load reached about 21 during the run from other sessions' jobs.
questions_for_g: none
