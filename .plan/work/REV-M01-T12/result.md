## RESULT REV-M01-T12
status: done
summary:
verdict: approve
reviewed: 06a8583c7229d3f4df38916539cce2897764e37d
Source review meets the criteria; test execution remains untestable in this sandbox.
changes: none
verification: `git diff --check main...HEAD` PASS; `clean-development doctor` FAIL, exit 1.
`.venv/bin/python -m pytest tests/test_read_guard_content_cmdlets.py tests/test_read_guard.py tests/test_graph_read_only.py tests/test_api_observed_ledger.py tests/test_exchange_protection.py` NOT RUNNABLE, exit 127.
First blocking lines: `ln: .venv: Operation not permitted`; `zsh:1: no such file or directory: .venv/bin/python`.
risks: (1) Verification blocked by sandbox; `merge.sh --verify` remains the execution gate. (2) Module contract-smoke and full suite not run: missing local environment and read-only placement. (3) Doctor reports GUI environment, DerivedData routing and lifecycle lock failures; no repairs attempted.
questions_for_g: none

### Findings

- MET: M01-T04 dependency is merged on main at 0e4d69d06d18f9669a3b5cf49ed6bbb6d34a8e98; task evidence: `.plan/work/M01-T04/result.md:3`.
- MET by inspection: explicit deny-list applies inside `_allowed_word`, shared by command checking and ledger classification: `src/azure_tenant_audit/adapters/read_guard.py:82`, `src/azure_tenant_audit/adapters/read_guard.py:366`, `src/azure_tenant_audit/adapters/read_guard.py:507`.
- MET by inspection: required Graph and Exchange names, attachment wildcard, case-insensitive matching and module-prefix stripping: `src/azure_tenant_audit/adapters/read_guard.py:85`, `src/azure_tenant_audit/adapters/read_guard.py:133`, `src/azure_tenant_audit/adapters/read_guard.py:355`.
- MET: tests assert refusal standalone, after pipes and inside wrappers, plus `classify_command` and `words_are_read`: `tests/test_read_guard_content_cmdlets.py:107`.
- MET: shipped-command helper and required metadata reads are covered: `tests/test_read_guard_content_cmdlets.py:70`, `tests/test_read_guard_content_cmdlets.py:127`.
- MET: module docstring names the deny-list: `src/azure_tenant_audit/adapters/read_guard.py:20`. `tests/test_read_boundaries.py` is unchanged.
- UNTESTABLE: criterion verification at `.plan/milestones/M01-boundary-proof.md:135`; sandbox prevented environment linking.
- DoD: this contributes to the content boundary item at `.plan/milestones/M01-boundary-proof.md:16`; it does not establish completion of that wider item. No other milestone DoD closure is claimed.
- Security: no new secrets, execution sinks, deserialisation, dependencies or permission changes; the new test file is mode 100644.
- Maintainability and architecture: shared enforcement avoids divergent guard rules; tests assert public behaviour; engine layering is preserved.
- Scope: both changed paths match `.plan/milestones/M01-boundary-proof.md:136`; no unexplained paths.
- Required changes: none.
- Non-blocking: `tests/test_read_guard_content_cmdlets.py:17` tests a subset of the extended deny-list. Include every named entry in the refusal matrix to protect future edits.
