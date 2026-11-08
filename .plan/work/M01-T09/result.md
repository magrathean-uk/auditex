## RESULT M01-T09
status: done
summary: `alerts.list` now sends a `fields` mask (`ALERT_FIELDS`) that omits `data`, so message snippets and subjects are never received. `groups.get` sends `GROUP_SETTING_FIELDS`, exactly the seven settings the normaliser reads. G8 and G9 in `_TEXT_EXPOSURES` are now `removed_at_request`. New tests cover the alert mask, the group `fields` argument and parity with `normalize.py`. All criteria are met.
changes: src/auditex/google_workspace/client.py, tests/test_read_boundaries.py (commit 6067d0c; tests/test_google_workspace.py unchanged, the new tests live in test_read_boundaries.py)
verification: `.venv/bin/python -m pytest tests/test_read_boundaries.py tests/test_google_workspace.py tests/test_google_collection_gaps.py tests/test_google_parity.py` - pass. Existing fixtures give the same normalised alert and group output. `git status --porcelain` is empty; `.venv` is a git-ignored link to the main checkout's venv.
risks: (1) The fake alert test applies the mask itself, so it proves the request argument and our handling, not Google's server-side behaviour. (2) `normalize.py` reads top-level `severity` and `status` on alerts; the real Alert resource nests them in `metadata`, which the mask keeps. This is unchanged behaviour. (3) The alert mask is the one the criteria gave, with no live-API check.
questions_for_g: none
