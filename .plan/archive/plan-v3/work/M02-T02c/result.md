## RESULT M02-T02c
status: done
summary: The digest comparison no longer depends on the run date. `expiry_days_remaining` and the `returned_value` that repeats it are normalised. Verdicts, findings and explainer text are still compared exactly. The baseline is re-recorded from 223fbaa. On the branch head, all 43 digests match.
changes: scripts/compare-run-outputs.py, tests/test_compare_run_outputs.py, tests/fixtures/contract-smoke-digests.json (one commit)
verification: `make lint` pass; `pytest tests/test_compare_run_outputs.py tests/test_parser_error_privacy.py` pass; `make contract-smoke` with PYTHONPATH=$PWD/src pass; `--digests` against the new fixture: "all 43 digests match (baseline commit 223fbaa5...)"; `git status --porcelain` empty.
risks:
- The only date-relative field in the eight runs is `expiry_days_remaining`. `expiry_state`, such as expiring versus expired, is still compared, so a long enough gap could flip it.
- `returned_value` is only masked when it equals an `expiry_days_remaining` nested in the same finding. A different `returned_value` still fails the comparison, and a test covers this.
- The baseline was recorded by running a copy of the new script from inside the 223fbaa worktree, so the fixture's commit field says 223fbaa. That copy and the worktree are removed.
questions_for_g: none
