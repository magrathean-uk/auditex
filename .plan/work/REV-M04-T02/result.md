## RESULT REV-M04-T02
status: partial
summary: verify deferred: heavy slot busy (`hostload.sh run --strict --wait 120`, exit 75). The pytest part of the verify passed when run on its own. Contract-smoke and the digest comparison are unchecked. Both changed paths match the task's files line, and the diff is exactly what DEC-016 allows.
verdict: approve
reviewed: eb1cbc0923bd79c4f65e10abf091a20fc5d02aae
changes: none (the `.venv` symlink in my worktree is git-ignored)
verification: `.venv/bin/python -m pytest tests/test_html_peak_harness.py tests/test_compare_run_outputs.py` pass. Full verify command (pytest, `make contract-smoke`, digest comparison) deferred, heavy slot busy; `merge.sh --verify` is the gate. Evidence in `.plan/work/REV-M04-T02/evidence.md`.
risks: (1) The recorded `commit` is aeac9aa, a revert commit, not a main sha. Its source tree equals main's, since main moved only in `.plan/`, so the baseline is valid. (2) Peak is up about 3 percent (607862784 to 626393088), so the 1.15 limit is now 720352051. (3) Contract-smoke and digests are unchecked here.
questions_for_g: none

### Findings
Criteria (M04-T02):
- Baseline re-recorded on current main, shareable profile, 90000 records: met. `benchmarks/html-peak-baseline.json:1-9` has records 90000, profile shareable, `workload_sha256` unchanged, and `unmasked_name_hits` 0 with `person_names` 45000.
- `test_committed_baseline_carries_names` asserts `person_names > 0`, keeps the `records == 90000` and `profile == "shareable"` asserts, and changes nothing else (DEC-016): met. `tests/test_html_peak_harness.py:111`, one line changed.
- `tests/test_html_peak_harness.py` and `tests/test_compare_run_outputs.py` pass: met (ran directly).
- `make contract-smoke` passes: untestable here (deferred). The author reports a pass.
- Digest comparison passes without a refresh: untestable here (deferred). The author reports "all 43 digests match". `tests/fixtures/contract-smoke-digests.json` is untouched in the diff.
- Files line: met. Only the two named paths changed.

DoD: none of the task's DoD items are closed by this task. It is a precondition for M04-T03 and the final peak guard.

Security: no secrets, no dependencies, no new code paths.

Maintainability: the history is three commits (record, revert, record) that cancel into one net change. This is harmless, and DEC-016 allows the single assertion change.

Required changes: none.

Suggestions (non-blocking): record a real main sha in `commit` rather than the revert sha. The `merge.sh --verify` gate must run contract-smoke and the digest comparison, since this review could not.

### Defect classes
none
