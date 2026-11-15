## RESULT M08-T11
status: done
summary: Review item 1 is fixed. The guide parity test now compares the App-Readonly bullets exactly against the default collector needs, and the SharePoint catalogue rows moved to a v1.0 table.
changes: tests/test_permission_docs_parity.py, docs/reference/api-call-catalog.md
verification:
- `.venv/bin/python -m pytest tests/test_permission_docs_parity.py tests/test_sharepoint_collector.py tests/test_intune_endpoint_collector.py tests/test_api_inventory.py tests/test_architecture_modules.py tests/test_setup_guide.py tests/test_docs_paths.py`: pass.
- `make contract-smoke`: pass.
- `make lint`: pass.
- Negative case, `test_guide_check_rejects_extra_missing_and_write_capable_scopes`: pass. It shows the guide check rejects an added `Calendars.Read`, `MailboxSettings.ReadWrite`, `Sites.FullControl.All` or `Mail.Read`, a removed `Reports.Read.All`, and an opt-in scope moved into the default list.
- Commit-time hooks: none run.
risks: The test depends on the guide marking opt-in bullets with "only when" and alternative-scope notes with "does not require"; a differently worded new bullet would count as a default scope.
questions_for_g: none

### Findings
1. Fixed. Parity now takes the bullets between `### App-Readonly` and the closing "Use `auditex probe live`" paragraph. Non-opt-in scopes must equal the collector needs exactly (so the write-capable and single-dot names the old filter missed now fail). Opt-in scopes must be disjoint from the needs, and neither the opt-in nor the note bullets may contain write-capable scopes.
2. Fixed (non-blocking suggestion). `docs/reference/api-call-catalog.md` now lists the three SharePoint rows in their own v1.0 table, not under "Current beta reads".
