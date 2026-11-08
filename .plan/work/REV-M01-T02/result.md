## RESULT REV-M01-T02
status: done
summary:
verdict: changes-required
reviewed: 479f33b57ffb881982ac963b758f16a390363fb0
All three round-2 corrections are present; the revised destination wording introduces an error.
Section E's HTTP operation set is complete and minimal.
Section G remains incomplete; no additional tenant-mutating path identified.
changes: none
verification: PASS - git status/diff, rg sweep, in-memory AST enumeration and source inspection; Google SDK source checked. Tests/builds/installs skipped as instructed. FAIL - developer-required clean-development doctor.
risks: Static review only. Doctor reported GUI/DerivedData routing failures, unverifiable lifecycle-lock ownership and unexpected dot-folders; no repairs attempted.
questions_for_g: none
### Findings

- transport-inventory.md:148 omits src/azure_tenant_audit/collectors/exchange_policy.py:126: Get-TransportRule explicitly selects ApplyHtmlDisclaimerText, an administrator-written message-body template. It is retained at src/azure_tenant_audit/normalize.py:2107. Add this exposure for T04 and distinguish retention from the stripping described in G.
- transport-inventory.md:39 incorrectly says cached OAuth credentials inherit the cache file's token_uri. Credentials.from_authorized_user_file at src/auditex/google_workspace/auth.py:120 overrides it with https://oauth2.googleapis.com/token. Correct A21, A24 and F; preserve the configurable destination description for newly acquired flow credentials. [Google SDK source](https://github.com/googleapis/google-auth-library-python/blob/main/google/oauth2/credentials.py).
- transport-inventory.md:83 and :103 identify incorrect subprocess coordinates: C1 calls subprocess.run at src/azure_tenant_audit/auth_runtime.py:47; C21 calls it at src/auditex/command_runner.py:109. Correct these before freezing the call-site inventory.
