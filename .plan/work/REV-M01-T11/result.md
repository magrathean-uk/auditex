## RESULT REV-M01-T11
status: done
summary:
verdict: approve
reviewed: 2246e060480f53f1819ddf0b1c565c817713370c
No required changes. Scope removal meets the criteria by inspection; runtime verification remains with the merge gate.
changes: none
verification: `git diff --check main...HEAD` passed; worktree clean; `git rev-parse HEAD` confirmed the reviewed SHA.
verification detail: `.venv/bin/python -m pytest tests/test_read_boundaries.py tests/test_google_workspace.py tests/test_scope_catalog.py tests/test_setup_guide.py tests/test_google_parity.py` not runnable, exit 127. First diagnostic: `zsh:1: no such file or directory: .venv/bin/python`.
risks: Verification not runnable because `.venv` is absent; the read-only sandbox prevents linking it. Contract-smoke, shipped-content parity and full-suite checks were not run and remain merge-gate responsibilities.
risks detail: `clean-development doctor` exited 1: GUI environment, DerivedData routing and lifecycle-lock failures; registration remains unconfirmed. No repairs attempted.
questions_for_g: none

### Findings

- MET, dependency: M01-T04 is merged into main as 0e4d69d06d18f9669a3b5cf49ed6bbb6d34a8e98, carrying its approval trailer; requirement at `.plan/milestones/M01-boundary-proof.md:122`.
- MET, scope removal: absent from `src/auditex/google_workspace/auth.py:12`, `src/auditex/google_workspace/auth.py:35`, `src/auditex/google_workspace/collectors.py:404` and `src/azure_tenant_audit/scope_catalog.py:12`; excluded from the exception table at `tests/test_read_boundaries.py:141`.
- MET, retained detection: `src/auditex/google_workspace/findings.py:1415` still flags operator-granted `gmail.settings.sharing`.
- MET, method coverage: `tests/test_read_boundaries.py:1643` names all eight method references; Google's scope lists confirm basic covers the existing reads, including [delegates.list](https://developers.google.com/workspace/gmail/api/reference/rest/v1/users.settings.delegates/list) and [forwardingAddresses.list](https://developers.google.com/workspace/gmail/api/reference/rest/v1/users.settings.forwardingAddresses/list).
- MET, operator guidance: grant instructions removed at `docs/guides/admin-permission-guide.md:199`, `docs/guides/admin-permission-guide.md:223` and `docs/guides/troubleshooting.md:101`; setup assertions updated at `tests/test_setup_guide.py:24`.
- MET by inspection, regression guard: `tests/test_read_boundaries.py:1634` asserts absence from requested scopes and scans source while retaining findings detection. Runtime result is untestable here.
- DoD checked: this task removes the pending scope exception and strict expected failure at `tests/test_read_boundaries.py:1630`; it does not close the whole boundary-proof DoD at `.plan/milestones/M01-boundary-proof.md:16`.
- Scope: `tests/test_google_workspace.py:136` and `tests/test_google_parity.py:406` are outside the original files line. Both assertion updates are explicitly authorised by main checkout `.plan/DECISIONS.md:106` (DEC-012). All other changed paths match; no unexplained scope creep.
- Security and maintainability: no introduced secrets, injection paths, unsafe deserialisation, dependency changes or file-mode changes. Permissions narrow; existing read calls and error handling remain intact.
- Required changes: none.
- Non-blocking suggestions: none.
