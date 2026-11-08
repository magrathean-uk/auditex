## RESULT M01-T09
status: partial
summary: Rebased onto main (M01-T07 now an ancestor). The only conflict was the field-mask constants in client.py, and I kept both sides. Item 2 is fixed. Item 3 is not done because it needs a file I don't own.
changes: src/auditex/google_workspace/client.py (conflict resolution, no logic change), tests/test_google_workspace.py (unchanged), tests/test_read_boundaries.py (kept both sides' rows; new collector-storage assertions)
verification: `.venv/bin/python -m pytest tests/test_read_boundaries.py tests/test_google_workspace.py tests/test_google_collection_gaps.py tests/test_google_parity.py` PASS. `git status --porcelain` empty.
risks: Alert severity and status are still read from the top level in `src/auditex/google_workspace/normalize.py:473`. The mask now keeps only `metadata`, so normalised alerts may lose them.
risks: `make contract-smoke` was not run; it is not in this task's verify command.
questions_for_g: Approve extending ownership to `src/auditex/google_workspace/normalize.py` so I can read `metadata.severity` and `metadata.status` with a fallback to the old top-level fields? I would add normalised-output assertions for both shapes.

### Findings
1. M01-T07 prerequisite: fixed. The rebase put M01-T07 into the branch history.
2. Stored-raw sentinel test: fixed. `test_alert_mask_drops_message_text_and_keeps_normalised_fields` now runs `GoogleAlertCenterCollector` and checks the stored payload. It asserts the sentinel is absent, `data` is absent and `metadata` is intact.
3. Normalised alert fields: not fixed. It needs the scope extension in the question above.
