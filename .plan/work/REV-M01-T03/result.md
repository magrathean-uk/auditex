## RESULT REV-M01-T03
status: done
summary:
verdict: changes-required
reviewed: ff059cfff1b8b46ee09784617028d528aad851d9
Two scanner gaps prevent the required boundary proof.
changes: none
verification: `git diff --check main...HEAD` PASS (exit 0); prescribed pytest not runnable (exit 127); `clean-development doctor` FAIL (exit 1).
risks:
- Not runnable: `.venv/bin/python -m pytest tests/test_http_verb_allowlist.py tests/test_read_guard.py tests/test_graph_read_only.py tests/test_transport_hygiene.py`. First error: `zsh:1: no such file or directory: .venv/bin/python`. Execution remains for merge.sh --verify.
- Storage doctor reports an unverifiable lifecycle-lock owner, GUI environment and Xcode routing mismatches, and existing dot-folder warnings. No configuration changed.
questions_for_g: none
### Findings
- MET: frozen inventory and decision precede implementation; entries carry classes and reasons: `.plan/DECISIONS.md:52`, `.plan/work/M01-T02/transport-inventory.md:114`, `tests/test_http_verb_allowlist.py:106`.
- NOT MET: exhaustive HTTP enumeration and rejection of every new non-GET site: `tests/test_http_verb_allowlist.py:198`, `tests/test_http_verb_allowlist.py:300`. See required changes.
- UNTESTABLE here: runtime Graph and mixed-batch rejection. Behavioural tests are present at `tests/test_read_guard.py:498` and `tests/test_read_guard.py:510`; execution is blocked by the missing interpreter.
- MET: guard comment names allowed methods and endpoint classes: `src/azure_tenant_audit/graph.py:46`.
- MET: scope restriction. All three changed paths match `.plan/milestones/M01-boundary-proof.md:55`; graph.py changes comments only. Out-of-scope paths: none.
- DoD: HTTP boundary proof at `.plan/milestones/M01-boundary-proof.md:15` remains unmet because of the scanner gaps. Other-provider routing is confirmed by the source checkout's author and reviewer dispatch files; approval and integration requirements at line 20 remain open.
- Security and maintainability: no added secrets, injection surface, unsafe deserialisation, dependencies or executable file modes found. Runtime tests assert rejection before token acquisition or network access.
Required changes:
1. `tests/test_http_verb_allowlist.py:204` - Detection requires attribute calls and omits Session.send. Standard forms such as `from requests import post; post(url)` and `session.send(prepared_request)` produce no classified transport site, allowing new POSTs to escape the test. Resolve imported transport names and prepared-request sends, or fail closed on unsupported transport forms; add regression cases asserting they fail until classified.
2. `tests/test_http_verb_allowlist.py:300` - Guarded variable-method sites are exempted by function and call name without a site count or proof that the sent method passed the guard. An additional `self.session.request(write_method, url)` inside PowerPlatformClient.request, with write_method set to POST after the existing guard, passes this exemption. Bind exemptions to the exact guarded sites and method flow, and add a regression proving an extra variable-method send is rejected.
Non-blocking suggestions: none
