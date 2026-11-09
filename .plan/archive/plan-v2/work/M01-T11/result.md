## RESULT M01-T11
status: done
summary: `gmail.settings.sharing` is gone from the requested scopes (committed in 93b5c00). The DEC-012 fix, committed in 2246e06, updates two assertions. `tests/test_google_workspace.py` now asserts the scope is absent from `write_capable_scopes`. `tests/test_google_parity.py` now expects `GMAIL_SETTINGS_SCOPES` to be the single `gmail.settings.basic` entry.
changes: tests/test_google_workspace.py, tests/test_google_parity.py (this session); earlier commit 93b5c00 holds the source and docs changes
verification: `.venv/bin/python -m pytest tests/test_read_boundaries.py tests/test_google_workspace.py tests/test_scope_catalog.py tests/test_setup_guide.py tests/test_google_parity.py` - pass. `git status --porcelain` is empty.
risks: I did not re-check the criterion that the Gmail settings reads are covered by `gmail.settings.basic` with a cited Google reference. It was in the earlier commit and is covered by `tests/test_read_boundaries.py`, which passes.
questions_for_g: none
