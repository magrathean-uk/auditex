## RESULT REV-M01-T03
status: done
summary:
verdict: changes-required
reviewed: 49ae52199001a8ce10ac78058536527bdf65aa03
Two urllib scanner gaps permit unclassified non-GET calls. Required verification is not runnable here.
changes: none
verification:
- PASS: diff and scope inspection, `git diff --check main...HEAD`, inventory completeness command.
- NOT RUNNABLE: `.venv/bin/python -m pytest tests/test_http_verb_allowlist.py tests/test_read_guard.py tests/test_graph_read_only.py tests/test_transport_hygiene.py`
- First diagnostic: `zsh:1: no such file or directory: .venv/bin/python`
- BLOCKED BY SANDBOX: supplemental `python3 -B` scanner probe; heredoc temporary-file creation refused. No workaround attempted.
- FAIL: `clean-development doctor` - routing discrepancies and unverifiable lifecycle lock.
risks:
- Runtime verification remains unconfirmed; module verification and contract smoke were skipped in this read-only environment. `merge.sh --verify` remains the gate.
- Doctor reports GUI environment and DerivedData routing discrepancies plus a lifecycle lock requiring recovery; project ownership is not assumed.
- Doctor reports unexpected dot-folders: ~/.agent-reach, ~/.asc, ~/.asc-web-session-locks, ~/.claude-science, ~/.grokbot, ~/.swiftpm, ~/dev/.claude.
questions_for_g: none
### Findings
Criteria checklist:
- MET: prerequisite inventory and freeze recorded at `.plan/DECISIONS.md:52`; allow-list entries match the frozen operations at `tests/test_http_verb_allowlist.py:125`.
- NOT MET: complete HTTP enumeration and rejection of new non-GET sites; omissions at `tests/test_http_verb_allowlist.py:289` and `tests/test_http_verb_allowlist.py:320`.
- UNTESTABLE: runtime Graph and batch refusal assertions exist at `tests/test_read_guard.py:499` and `tests/test_read_guard.py:511`; execution unavailable.
- MET: allowed methods and endpoint classes documented at `src/azure_tenant_audit/graph.py:46`.
- MET: all three changed paths match `.plan/milestones/M01-boundary-proof.md:55`; graph changes are comments only. No scope creep.
DoD:
- NOT MET: HTTP boundary proof at `.plan/milestones/M01-boundary-proof.md:15`, owing to the scanner gaps.
- PENDING: approval and integration evidence at `.plan/milestones/M01-boundary-proof.md:20`. Dispatch records show different providers for author and reviewer.
Required changes:
1. [P1] `tests/test_http_verb_allowlist.py:289`: aliased urllib imports disappear from the scan. `_classify_import` returns None for urllib Request/urlopen, then this branch returns immediately when the local name is an alias. Consequently, `from urllib.request import urlopen as send; send(u, data=b'x')` produces no site. Apply urllib semantics using the resolved import origin and add regression cases for aliased Request and urlopen, asserting classification rejection.
2. [P1] `tests/test_http_verb_allowlist.py:320`: opener sends depend on the receiver spelling containing `opener`. `from urllib.request import build_opener; client = build_opener(); client.open(u, data=b'x')` is ignored, although it sends POST. Track opener construction and receiver provenance, and add a regression proving this new site fails classification.
Security and maintainability:
- No additional secrets, injection, permissions, unsafe deserialisation or dependency issues found. New file mode is 100644.
- Behavioural regression tests cover earlier repairs, but omit the two urllib forms above.
Non-blocking suggestions: none
