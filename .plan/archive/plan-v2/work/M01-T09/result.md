## RESULT M01-T09
status: done
summary: Alerts now read severity and status from `metadata`, falling back to the top-level fields (DEC-014). The alerts.list and groups.get masks and the G8/G9 dispositions were already in place. Review items 2 and 3 are fixed and item 1 is answered below.
changes: src/auditex/google_workspace/normalize.py, tests/test_google_workspace.py (commits 8a9a131 and ca63a12; masks and sentinel test were in earlier commits 1ada017 and 398c679)
verification: the required pytest command (test_read_boundaries, test_google_workspace, test_google_collection_gaps, test_google_parity) PASS; `make contract-smoke` PASS; worktree clean.
risks: 1) The first of my two commits, 8a9a131, has a failing new test; ca63a12 fixes it, so only the branch head is green. 2) `git merge-base --is-ancestor aad9aa0` fails for the M01-T07 sha. Commit 19c7ea7 (Gmail settings masks) is on the branch, so I read this as a rebased copy of T07; I did not check that the content matches. 3) I did not run the full `make test`.
questions_for_g: none
### Findings
1. M01-T07 prerequisite: answered, not fixed. The T07 change is on the branch as 19c7ea7 and the orchestrator should confirm it at integration.
2. Sentinel test through the collector: fixed in 398c679. It runs GoogleAlertCenterCollector and asserts that the stored payload has no snippet or subject, no `data` key, and keeps `metadata`.
3. Metadata severity and status: fixed. `_alert_metadata` supplies the metadata values with a top-level fallback, and a new test covers both shapes in the normalised output.
