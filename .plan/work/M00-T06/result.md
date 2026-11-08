## RESULT M00-T06
status: done
summary: Cause was the gate environment, not packaging: the gate's pytest temp dir sat inside the checkout, so the loader added a "dev" route and the installed-only assertion failed. Reproduced (passes with normal temp, fails with temp inside a checkout).
Fix (test only): run from the filesystem root when a parent folder looks like a checkout; assert the run directory is not one; route list must be non-empty and installed-only. Same proof, slightly stricter.
Criteria: cause diagnosed and recorded in notes - met; environment cause handled without weakening the test - met; whole file passes, no other test touched - met.
Notes: .plan/work/M00-T06/notes.md
changes: tests/test_explainer_integration.py (commit d16b0f1)
verification: .venv/bin/python -m pytest tests/test_explainer_integration.py - pass (37 passed) on committed head; module command pytest tests/test_explainer_integration.py tests/test_explainer_catalogue_drift.py - pass (47 passed); fixed test with --basetemp under a fake checkout in $TMPDIR - pass; git status --porcelain empty (.venv link is git-ignored)
risks: The test uses the private helper resources._looks_like_dev_root, so renaming it breaks the test loudly. The fallback runs the subprocess from "/" (read-only, harmless).
questions_for_g: none
