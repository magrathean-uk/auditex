## RESULT M01-T03
status: done
summary: Both REV-M01-T03 items are fixed in `tests/test_http_verb_allowlist.py`; `graph.py` and `test_read_guard.py` are unchanged this round.
Item 1 fixed: names imported from `requests`, `httpx`, `urllib3`, `aiohttp`, `http.client` or `urllib.request` now resolve to their verb, so `from requests import post` (with or without an alias) and `requests.Request('POST', u)` are caught. Imported transport callables the scanner does not recognise, and every `.send(...)`, now count as variable-method sites and fail until classified. Verb methods taken as values (`post = s.post`) or through `getattr(s, 'delete')` are also caught.
Item 2 fixed: `GET_ONLY_GUARDED` entries now carry an exact site count. Each guarded site must send the function's own `method` parameter, never reassigned. The function must check that parameter first (A8 and the Graph dispatch), or pass it to a receiver typed `PowerPlatformClient` (A9). Regression tests show that the reviewer's `write_method` case, a reassigned `method`, a second send, a missing guard and an untyped receiver all fail.
Criteria: allow-list limited to the frozen inventory, met; every HTTP call site under `src/` enumerated and new non-GET sites fail, met (now fail-closed); runtime Graph and `$batch` refusal, met (existing tests run and pass); `graph.py` guard comment, met.
changes: tests/test_http_verb_allowlist.py (commit 49ae521 on task/M01-T03-http-allowlist)
verification: `.venv/bin/python -m pytest tests/test_http_verb_allowlist.py tests/test_read_guard.py tests/test_graph_read_only.py tests/test_transport_hygiene.py` passed (exit 0); module command `.venv/bin/python -m pytest tests/test_read_guard.py tests/test_graph_read_only.py tests/test_contract.py && make contract-smoke` passed (exit 0, bundle seal verified); `git status --porcelain` is empty.
risks:
- Remaining blind spots: `getattr` with a computed name, and Google API client `.execute()` chains, which M01-T04 covers.
- Fail-closed rule: any future `.send(...)` under `src/`, including on a generator or socket, has to be added to the list. There are none today.
- The branch is behind `main` on unrelated paths; no rebase was asked for, so merge.sh decides.
questions_for_g: none
