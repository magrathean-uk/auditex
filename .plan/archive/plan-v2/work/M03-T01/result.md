## RESULT M03-T01
status: done
summary: Fixed the one review item. `docs/reference/output-contract.md` no longer lists `status: skipped` replay coverage rows as already present in 1.2.4. The "Documented here for the first time" list drops that clause (line 239). The "Added since 1.2.4" list (line 237) now gains skip preservation on offline replay coverage rows, citing 3e8c1bd.
changes: docs/reference/output-contract.md
verification: the grep checks for version 1.3.0, the `## [1.3.0]` changelog heading and the `| 1.3.x | Yes |` SECURITY row, plus `pytest tests/test_architecture_modules.py tests/test_contract.py` - pass on the committed head; `git status --porcelain` empty
risks: the fix touched line 237 as well as owned line 239, because the review asked for the claim to move into the "new since 1.2.4" list
questions_for_g: none
