## RESULT REV-M00-T06
status: done
summary:
verdict: approve
reviewed: 9a89ee296ae38041cc8d5415c2c8208de7f1e2aa
The first review's required change is fixed. `parse_as_of` now refuses dates outside 1970-01-01 to 2999-12-31. All three offline entries (engine, auditex run, auditex google run) exit 2 on 0001-01-01, 9999-12-31, 1969-12-31 and 3000-01-01, with no traceback and no run folder; 1970-01-01 and 2999-12-31 run to exit 0.
The window is stated in the help and in output-contract.md, and tests cover it. The changed lines add no defect. Full table in .plan/work/REV-M00-T06/evidence.md (second-review section).
changes: none (review only: appended a second-review section to .plan/work/REV-M00-T06/evidence.md in the main checkout; .venv link and git-ignored outputs/ in the worktree)
verification: Makefile awk check pass; pytest test_offline_as_of, test_cli_abbreviations, test_cli, test_google_workspace pass; make lint pass; make contract-smoke pass and compare-run-outputs --digests pass (43 of 43 match), both with PYTHONPATH set to the worktree src; make test not run (brief: once per merged batch); 18 probe runs into $TMPDIR as tabled in evidence.md
risks: The linked main-checkout .venv imports the main checkout's code, so without PYTHONPATH `make contract-smoke` tested main and failed on `--as-of`. The merge gate must run with an environment that imports the code under test.
risks: No bundle field records the as-of date, so a replay judged at an old date looks the same as one judged now (carried over from the first review, by design).
questions_for_g: none
### Findings
Criteria (second review, diff-scoped 3b6c0b0..HEAD):
- Out-of-window dates are a usage error on the Microsoft 365 entries: met. src/azure_tenant_audit/cli.py:137 (window constants), :149 (check). The pattern only allows fixed-width ASCII digits, so comparing them as strings is the same as comparing the dates.
- The same on the Google entry: met. src/auditex/cli.py:12 and :388 reuse `parse_as_of`; the probe exits 2.
- Exit 2, no traceback, no run folder: met. tests/test_offline_as_of.py:218 runs the three real entries as subprocesses and checks returncode 2, no Traceback, no `out`. My probes agree.
- Window stated in help and docs: met. cli.py:141 (AS_OF_HELP, shown on both `--help` outputs); docs/reference/output-contract.md:994.
- Tests cover the window: met. tests/test_offline_as_of.py:144 (both ends and the day inside each accepted), :155 (OUT_OF_WINDOW in INVALID_DATES), :197 (extremes through every entry parser).
- Earlier criteria and DoD (DEC-005 smoke dates): unchanged since the first review and still met. The awk check passes and all 43 digests match.
Security: no secrets, dependencies, injection or file-mode changes. The error message does not echo the date (existing check at test_offline_as_of.py:204).
Scope: the three changed paths (cli.py, test_offline_as_of.py, output-contract.md, offline replay paragraph) are all on the files line.
Required changes: none.
Suggestions (non-blocking):
- docs/guides/product-manual.md:207 could state the 1970-01-01 to 2999-12-31 window next to "A malformed date ... refused with exit status 2".
