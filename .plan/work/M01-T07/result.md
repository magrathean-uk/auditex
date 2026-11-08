## RESULT M01-T07
status: done
summary: The send-as fields mask now keeps every field except `signature`: `displayName`, `replyToAddress`, `isPrimary`, `isDefault`, `treatAsAlias`, `smtpMsa`, `verificationStatus`. Live output now keeps the same metadata as replay, minus the DEC-012 text deletions. Review item 1 is fixed. The non-blocking suggestion is also done: the test now asserts the exact send-as mask, no `*` wildcard in any mask, and that `isPrimary` and `displayName` are present. All criteria are met (T07 commit c5146ab, review fix aa0a574).
changes: src/auditex/google_workspace/client.py, tests/test_google_workspace.py
verification: `.venv/bin/python -m pytest tests/test_read_boundaries.py tests/test_google_workspace.py tests/test_google_collection_gaps.py tests/test_data_minimisation.py tests/test_google_parity.py` PASS. `git status --porcelain` is empty.
risks: I did not run `make contract-smoke` or the shipped-content parity test; the criteria don't require either. The fake Gmail service in the tests ignores `fields`, so a mask's effect on live data is only checked by inspection.
questions_for_g: none
