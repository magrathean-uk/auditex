## RESULT REV-M01-T09
status: done
summary:
verdict: changes-required
reviewed: 6067d0c0b8afebf8ef538e673203401d863ded03
M01-T07 prerequisite is missing; alert preservation and stored-raw assertions are incomplete.
changes: none
verification: `git diff --check main...HEAD` PASS; M01-T04 ancestry PASS; M01-T07 ancestry FAIL.
Required verify: `.venv/bin/python -m pytest tests/test_read_boundaries.py tests/test_google_workspace.py tests/test_google_collection_gaps.py tests/test_google_parity.py` NOT RUNNABLE.
First diagnostic: `zsh:1: no such file or directory: .venv/bin/python`.
risks: Verification not runnable: missing `.venv`; creating its link is blocked by sandbox. `merge.sh --verify` remains the gate.
`make contract-smoke` and full suite skipped because the sandbox is read-only.
`clean-development doctor` FAIL: GUI environment, DerivedData routing and lifecycle-lock checks; also reported unexpected dot-folders. No repairs attempted.
questions_for_g: none
### Findings
Criteria checklist:
- NOT MET - dependency order: `.plan/milestones/M01-boundary-proof.md:106`; M01-T04 is an ancestor, but M01-T07 commit aad9aa0794b8c6a15a657ddd710bad6f5f349eec is not.
- MET - exact alert mask excludes `data` and retains pagination: `src/auditex/google_workspace/client.py:35`, `:268`.
- NOT MET - alert normalised-field preservation: `src/azure_tenant_audit/normalize.py` is unrelated; the relevant reads are `src/auditex/google_workspace/normalize.py:473`, which still expect top-level severity/status while the mask retains metadata.
- NOT MET - stored-raw sentinel test: `tests/test_read_boundaries.py:1784` checks client-returned rows, without exercising collector storage.
- MET - group mask matches all seven normaliser settings, excludes both text fields, and is asserted through a fake service: `src/auditex/google_workspace/client.py:36`; `tests/test_read_boundaries.py:1791`.
- MET - G8/G9 dispositions updated: `tests/test_read_boundaries.py:192`.
- UNTESTABLE - existing-fixture alert/group output parity: `.plan/milestones/M01-boundary-proof.md:110`; required suite could not run.
- DoD contribution remains incomplete: `.plan/milestones/M01-boundary-proof.md:16`; request masks are present, but the alert proof above is incomplete. Other DoD items are outside this task.
- Scope: both changed paths are permitted by `.plan/milestones/M01-boundary-proof.md:112`; no unexplained paths.
- Security/maintainability: no added secrets, injection sinks, permission changes, unsafe deserialisation or dependencies; no new dead code found.

Required changes:
1. `.plan/milestones/M01-boundary-proof.md:106`: satisfy the prerequisite by integrating M01-T07 first, then review the resulting frozen task head.
2. `tests/test_read_boundaries.py:1784`: extend the sentinel test through the collector and raw-output storage; assert neither message snippet nor subject appears in the stored record.
3. `src/auditex/google_workspace/normalize.py:473`: the pre-existing metadata/top-level mismatch prevents the stated preservation proof. Obtain the scope extension to read metadata severity/status with legacy fallback, and add normalised-output assertions for both shapes.

Non-blocking suggestions: none.
