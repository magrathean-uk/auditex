## RESULT M01-T04
status: done
summary: All three items in REV-M01-T04/result.md are fixed, each with new tests. (1) The DEC-010 scopes are an accepted-exception table with blast radius, reason and calls, proved list/get only; an unlisted write-capable scope fails, and gmail.settings.sharing is the single strict xfail naming M01-T11. (2) Subprocess launches are matched by import origin, so `as` aliases, renamed imports and assigned aliases are found, and an aliased launch with input the scan cannot trace is reported. (3) Google: touching an HttpRequest member makes a name a request, so inspected requests (bound or inline `.uri`) are kept. All criteria met: content, command, m365 and Google method checks are unchanged and pass, and the scope rule now holds with the DEC-010 exceptions.
changes: tests/test_read_boundaries.py (commit 016718a); notes in .plan/work/M01-T04/notes.md (Round 3)
verification: `.venv/bin/python -m pytest tests/test_read_boundaries.py tests/test_api_inventory.py tests/test_api_observed_ledger.py tests/test_exchange_protection.py tests/test_pack_integrity_and_permissions.py`: pass (168 passed, 1 xfailed, the named sharing xfail); `.venv/bin/python -m pytest tests/test_read_guard.py tests/test_graph_read_only.py tests/test_contract.py && make contract-smoke`: pass; git status --porcelain: empty
risks:
- M01-T11 must remove the strict xfail marker when it drops gmail.settings.sharing: the test XPASS-fails until it does.
- Documented scanner limits L1-L4 (non-subprocess launchers, dynamic callee lookup, requests held in containers or fetched via getattr, per-module handle naming) go to BACKLOG per DEC-011; see notes.md.
- The SessionStart hook reported a clean-development lifecycle registration failure; not repaired here (worker scope).
questions_for_g: none
