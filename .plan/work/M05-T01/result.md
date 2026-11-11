## RESULT M05-T01
status: done
summary: Shadowed callees: if the module binds a read-only hand-off or transparent-conversion name itself (def, class, assignment, import, star import, method, parameter), the shortcut is switched off and the launch fails closed; `graph_url` and `VettedCommand` keep it only when imported from, or defined in, their own module.
Undeclared import, plain `with`, `def`, `class`, `except` and `match` bindings now count in their scope; a comprehension walrus binds in the scope around it; a name read in a class body is checked in the class's own names and in the outer scopes, so no value counts as proven where it did not before.
Planted cases: 62 fail before and pass after, case by case in `.plan/work/M05-T01/evidence.md`; 2 neighbour tests pass both times. The real-source exact-match tables are unchanged.
Citations now read "v2 DEC-011" (12 lines). Review items: venv linked and PYTHONPATH set; INV4 facts, DEC-008/009 and BACKLOG read; per-case before/after recorded; only focused pytest and lint run; repo-relative paths only.
Criteria: shadow rule met; binding union met; class namespace met; proven-literal rule kept (existing tests pass); v2 citation met. Further classes found are listed for M05-T03 in `.plan/work/M05-T01/notes.md`.
changes: tests/test_read_boundaries.py
verification: `.venv/bin/python -m pytest tests/test_read_boundaries.py` pass (323 passed, on 393b1af after the rebase); `make lint` pass (after the rebase); module command `.venv/bin/python -m pytest tests/test_read_guard.py tests/test_graph_read_only.py tests/test_contract.py && make contract-smoke` pass (before the rebase); the planted block was also run against the old scanner: 62 failed, 2 passed as expected. Skipped: `make test`, which the review defers to the merge batch.
risks: Further classes still open, for M05-T03: an attribute call on another object or source module (`helpers.info(ARGV)`) still takes the shortcut; a bare call follows any function of that name in the module even when the call site binds the name otherwise; string-method, `.get` and append matching ignores what the module binds.
A declared re-export two modules away was followed before and is now unresolved. This is narrower, and no test or source depends on it.
The limits table in `docs/reference/security-privacy.md` (M05-T03) still lists the closed rows, and this file's "DEC-010" Google-scope citations also clash with the live log.
questions_for_g: none
