## RESULT REV-M01-T02
status: done
summary:
verdict: changes-required
reviewed: 27759ed52ad1211e1e7b5c11b7203ba252fb3666
Round-1 corrections verified except SDK refresh completeness; accepted class interpretations applied.
Section E names operations and removes unnecessary GET exceptions, but remains incomplete.
changes: none
verification: PASS - git status, rg sweep, in-memory AST enumeration and source inspection; SDK documentation checked. Tests/builds/installs skipped as instructed. FAIL - developer-required clean-development doctor.
risks: Static review only; doctor reported GUI/DerivedData routing failures, unverifiable lifecycle-lock ownership and unexpected dot-folders. No repairs attempted.
questions_for_g: none
### Findings
- transport-inventory.md:140 omits shipped reads that receive user-authored body text: src/auditex/google_workspace/client.py:300 fetches vacation-responder bodies; :297 fetches signatures; src/azure_tenant_audit/collectors/mailbox_forwarding.py:255 fetches automatic-reply bodies. Minimisation occurs after receipt (:302 and :273 respectively). Record these concrete exposures for T04; stripping output does not enforce the no-read boundary.
- transport-inventory.md:126 covers lazy service-account refresh only. OAuth credentials loaded at src/auditex/google_workspace/auth.py:120 or acquired at :125 also refresh during SDK execute calls, independently of the explicit :122 refresh. Add that named class-2 path and cover subsequent service-account refreshes too. [SDK refresh behaviour](https://googleapis.dev/python/google-auth-httplib2/latest/google_auth_httplib2.html).
- transport-inventory.md:40 incorrectly fixes the service-account destination to oauth2.googleapis.com/token: src/auditex/google_workspace/auth.py:102 inherits token_uri from the supplied key file. The flow constructed at :124 likewise uses client-configured authorisation/token URIs. Record these configurable destinations and absence of application-level pinning. [Service-account implementation](https://google-auth.readthedocs.io/en/latest/_modules/google/oauth2/service_account.html), [OAuth flow documentation](https://googleapis.dev/python/google-auth-oauthlib/latest/reference/google_auth_oauthlib.flow.html).
