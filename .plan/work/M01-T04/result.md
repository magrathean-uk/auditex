## RESULT M01-T04
status: done
summary: All four REV-M01-T04 items fixed; 1 non-blocking item fixed. Branch task/M01-T04-read-boundaries at 273983e.
- Item 1 fixed: the endpoint scan now follows names, imports, loops, appends and function arguments, so params set away from the call (the review's `endpoint = "/users"` case) are judged with their endpoint. Requests that stay unresolved are a closed table and are still judged on any params that are visible. 8 new regression tests.
- Item 2 fixed: command sites are strings that actually reach a process or runner call, matched case-insensitively. Docstrings, help text, label tables and stderr matches are no longer sites. Runner calls the scan can't fully trace are a closed table of 21 entries, each with a reason. New regression tests cover runnable commands and documentation text.
- Item 3 fixed: a Google request built, assigned and run later is now counted, as is an inline `_service(...)` / `self._service(...)` / `build(...)` chain. A name only counts as a resource handle when another method is called on it.
- Item 4 fixed: scopes must be read-only or metadata-only. The 5 write-capable scopes are listed as open gaps and run as strict expected failures, not exemptions. A test keeps that list limited to real, still-requested gaps. Non-blocking item fixed: the unreachable loop is gone with the old matcher.
- Criteria: content-read scan met; executable-only command scan with the wrapper table and m365 guard met; Google methods met; Google scopes enforced, with 5 existing scopes reported as gaps (see risks); gaps outside the owned files reported as tasks in .plan/work/M01-T04/notes.md, not fixed here. api_inventory.py not changed: no classifier gap found.
changes: tests/test_read_boundaries.py
verification:
- .venv/bin/python -m pytest tests/test_read_boundaries.py tests/test_api_inventory.py tests/test_api_observed_ledger.py tests/test_exchange_protection.py tests/test_pack_integrity_and_permissions.py: pass (171 passed, 5 xfailed), re-run on committed head, exit 0
- module command: .venv/bin/python -m pytest tests/test_read_guard.py tests/test_graph_read_only.py tests/test_contract.py: pass (267 passed); make contract-smoke: pass
- git status --porcelain: empty
risks:
- The DoD stays open until the scope gaps are closed or accepted: 5 Google scopes still break the rule, now shown as strict expected failures. New tasks in notes.md: FU-SCOPE-1 (drop gmail.settings.sharing; basic covers its two calls) and FU-SCOPE-2 (decide on the 4 scopes Google offers no read-only form for).
- The review also noted retained text exposures G6, G8, G9 and G10. They are settings text, not message, mail, file or attachment content under the classifier, so they don't breach this criterion; they stay a follow-up task (FU-TEXT).
- The tracing is static and cannot see across modules through method calls or config-loaded values; those paths are covered by the closed tables and the config command-field test. A new path the scan can't trace fails until someone reviews it into a table.
questions_for_g:
- FU-SCOPE-2: keep the four scopes with no read-only form (admin.directory.user.security, apps.alerts, gmail.settings.basic, apps.groups.settings) as documented gaps, put them behind an opt-in, or drop the sections that need them? Recommendation: an opt-in, because the default run would then meet the read-only rule.
