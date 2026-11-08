## RESULT M01-T12
status: done
summary: Added a shared content cmdlet deny-list for the runtime guard and ledger classification, including case-insensitive and module-prefixed names.
summary: Tests cover standalone, piped and wrapped refusals, classification, shipped commands and permitted metadata cmdlets. The module docstring names the deny-list.
changes: src/azure_tenant_audit/adapters/read_guard.py; tests/test_read_guard_content_cmdlets.py
verification: `.venv/bin/python -m pytest tests/test_read_guard_content_cmdlets.py tests/test_read_guard.py tests/test_graph_read_only.py tests/test_api_observed_ledger.py tests/test_exchange_protection.py` - pass, 450 tests.
verification: `.venv/bin/python -m pytest tests/test_read_guard.py tests/test_graph_read_only.py tests/test_contract.py` - pass, 276 tests; `make contract-smoke` - pass; `git diff --check` - pass; status contains only owned files.
risks: `clean-development doctor` reported GUI environment routing, Xcode DerivedData routing and lifecycle lock failures. No repair attempted.
questions_for_g: none
dispatch: committed a91ce17 on task/M01-T12-guard-content-cmdlets (2 paths: src/azure_tenant_audit/adapters/read_guard.py, tests/test_read_guard_content_cmdlets.py)
