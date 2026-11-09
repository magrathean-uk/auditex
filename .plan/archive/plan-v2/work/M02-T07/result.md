## RESULT M02-T07
status: done
summary: Line 17 of the third-party notice now carries G's approved bullet verbatim, with the full vendored path. The notices entry is gone from the exemption list in tests/test_docs_paths.py. Both changes are in one signed-off commit on task/M02-T07-legal-notice, sha ce0dff8. I linked the main checkout's .venv into the worktree; it is git-ignored and the working tree is clean.
changes: docs/legal/third-party-notices.md, tests/test_docs_paths.py
verification: `.venv/bin/python -m pytest tests/test_docs_paths.py` pass; `! grep -n 'third-party-notices' tests/test_docs_paths.py` pass; grep for the full vendored path in the notice pass (1 match). The brief's one-line verify chains these three. I ran them as separate commands rather than as one chained line.
risks: none
questions_for_g: none
