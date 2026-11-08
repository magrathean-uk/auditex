## RESULT REV-M01-T04
status: done
summary:
verdict: changes-required
reviewed: 06cb949c13a3168aa8c528a495e2a887677bb126
Static review found gaps in endpoint, command and Google-call coverage, plus scope exemptions broader than the criteria.
changes: none
verification:
- PASS: git diff --check main...HEAD; inventory existence/classification check; clean worktree.
- NOT RUNNABLE: .venv/bin/python -m pytest tests/test_read_boundaries.py tests/test_api_inventory.py tests/test_api_observed_ledger.py tests/test_exchange_protection.py tests/test_pack_integrity_and_permissions.py
- First diagnostic: zsh:1: no such file or directory: .venv/bin/python
- FAIL: clean-development doctor reported routing mismatches and an unverifiable lifecycle-lock owner.
risks:
- Pytest results remain unverified; merge.sh --verify remains the gate.
- Auxiliary python3 stdin probes were blocked by sandbox temporary-file restrictions; examples below are static findings.
- Storage ownership remains unverified; doctor also reported unexpected dot-folders and unmanaged entries. No repairs attempted.
questions_for_g: none

### Findings

Criteria checklist:
- MET: M01-T02 dependency exists and the changed file is disjoint from M01-T03: .plan/milestones/M01-boundary-proof.md:58; tests/test_read_boundaries.py:25.
- NOT MET: endpoint scanning can lose content-bearing request parameters: tests/test_read_boundaries.py:262.
- NOT MET: command scanning misses executable lower-case commands and includes documentation strings: tests/test_read_boundaries.py:351, tests/test_read_boundaries.py:412.
- NOT MET: Google enumeration omits assigned requests; scope exceptions exceed the stated rule: tests/test_read_boundaries.py:646, tests/test_read_boundaries.py:731.
- MET: existing production gaps are recorded as follow-up tasks without changing other modules: .plan/work/M01-T04/result.md:9 in the source checkout.
- UNTESTABLE: required verification, because the worktree has no .venv/bin/python.

DoD:
- NOT MET: the boundary-proof item remains open because of the coverage gaps and acknowledged content exposures: .plan/milestones/M01-boundary-proof.md:16; tests/test_read_boundaries.py:125.
- Cross-provider review routing is satisfied by the author/reviewer dispatch records. Approval and integration requirements remain outstanding: .plan/milestones/M01-boundary-proof.md:20.

Required changes:
1. tests/test_read_boundaries.py:262 - Parameters are attached to the argument AST node, rather than its resolved endpoint. With `endpoint = "/users"` followed by `client.get_json(endpoint, params={"$expand": "messages"})`, the scanned literal receives empty parameters. Resolve endpoint bindings or fail closed on unresolved request associations; add a regression case.
2. tests/test_read_boundaries.py:351 - `import-module ExchangeOnlineManagement` is skipped because it lacks conventional capitalisation, a second cmdlet or a parameter flag. Meanwhile, line 412 scans every qualifying string, including returned help text. Identify executable runner inputs and command lists structurally, handle PowerShell case-insensitively, and test both executable and documentation examples.
3. tests/test_read_boundaries.py:646 - Every assigned API call is assumed to bind a resource handle. `request = service.users().delete(userKey="victim"); request.execute()` therefore omits the mutation. Inline `_service(...).users().delete(...).execute()` also lacks a recognised service-name root. Track request construction separately from resource accessors and add regressions for both forms.
4. tests/test_read_boundaries.py:731 - A `write_capable` catalogue label permits five scopes without establishing the required read-only or metadata-only restriction. Enforce the stated rule and report incompatible existing scopes as unresolved gaps, or obtain an explicit criteria amendment before accepting those exemptions.

Security and scope:
- No new credentials, dependencies, tenant mutations, unsafe deserialisation or executable file modes were introduced.
- Scope creep: none. The sole changed path, tests/test_read_boundaries.py, matches the files line.
- Existing content exposures are reported, but their follow-up status does not prove the milestone's no-content-read boundary.

Non-blocking:
- tests/test_read_boundaries.py:377 - Remove the duplicated unreachable loop after `return False`.
- Full-suite and contract-smoke checks were not run in this read-only review.
