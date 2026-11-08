## RESULT REV-M01-T04
status: done
summary:
verdict: changes-required
reviewed: 273983eea274e49647ef0dd83a5527d07b53e10c
Three required changes: scope failures are suppressed, subprocess aliases evade discovery, and Google request inspection can hide writes.
changes: none
verification:
- git diff main...HEAD: reviewed; only tests/test_read_boundaries.py changed.
- git diff --check main...HEAD: pass; working tree clean.
- Prescribed verification: not runnable, exit 127. First line: "zsh:1: no such file or directory: .venv/bin/python".
- Additional scanner probes: blocked by sandbox before execution; "can't create temp file for here document: operation not permitted".
- Module tests not runnable without .venv; contract smoke skipped in the read-only sandbox.
- clean-development doctor: fail; lifecycle owner unverifiable, GUI environment and DerivedData routing mismatches.
risks:
- Not runnable: `.venv/bin/python -m pytest tests/test_read_boundaries.py tests/test_api_inventory.py tests/test_api_observed_ledger.py tests/test_exchange_protection.py tests/test_pack_integrity_and_permissions.py`. merge.sh --verify remains the gate.
- Storage lifecycle registration remains unresolved; no ownership or configuration repair attempted.
- DEC-007 text exposures G6/G8/G9/G10 remain follow-ups, without a final accepted or removed disposition.
questions_for_g: none
### Findings
Criteria checklist, assessed by source inspection unless stated:
- Met: M01-T02 prerequisite and disjoint ownership; .plan/DECISIONS.md:61 and tests/test_read_boundaries.py:49.
- Met: content classifier scans collector/adapter literals and collector definitions; tests/test_read_boundaries.py:864 and tests/test_read_boundaries.py:948.
- Not met: complete executable-command discovery; tests/test_read_boundaries.py:980. Wrapper tables, ordinary-wrapper refusal, DSC VettedCommand and m365 write-refusal checks are present.
- Not met: Google method enumeration and scope enforcement; tests/test_read_boundaries.py:1358 and tests/test_read_boundaries.py:1522.
- Met: gaps outside owned source files are reported as follow-up tasks; .plan/work/M01-T04/result.md:15. api_inventory.py remains unchanged.
- Untestable: required verification; .plan/milestones/M01-boundary-proof.md:63, interpreter absent.
- Met: files constraint; the sole changed path is authorised. Unexplained scope creep: none.
- DoD remains open: .plan/milestones/M01-boundary-proof.md:16 is not proven. Author acknowledges this at .plan/work/M01-T04/result.md:15.
- Review routing uses different providers, confirmed from dispatch records; integration evidence under .plan/milestones/M01-boundary-proof.md:20 remains pending.
- Security/maintainability: no added credentials, dependencies, unsafe deserialisation, permission changes or runtime injection paths found. Behavioural regression tests are present; coverage defects follow.

Required changes:
1. tests/test_read_boundaries.py:1522: strict xfail converts five prohibited scope failures into a successful suite outcome. Remove the expected-failure suppression. Keep the boundary gate failing until separately scoped repairs or an approved criteria change resolve the existing scopes; reporting follow-ups does not satisfy this criterion.
2. tests/test_read_boundaries.py:980: subprocess discovery checks spelling rather than canonical imports. `from subprocess import run as launch; launch(["pwsh", "-Command", "Set-Mailbox x"])` and `import subprocess as sp; sp.Popen(...)` escape both command discovery and unresolved-input reporting. Resolve module/function aliases and add regression cases that reject these executable writes.
3. tests/test_read_boundaries.py:1358: any non-execute attribute access marks a name as a resource handle. Consequently, assigning `service.users().delete(...)` to `request`, inspecting `request.uri`, then calling `request.execute()` suppresses the delete at line 1415. Distinguish resource accessors from request objects, retain executed requests regardless of property inspection, and add this regression.

Optional suggestions: none.
