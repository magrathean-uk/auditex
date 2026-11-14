## RESULT M08-T01
status: partial
summary: Partial because the host sitting is stopped at step 2d (BASELINE-FAIL), so make contract-smoke was not run. Checks covered the full 45-minute window: 10:24-11:06 in the cut-off run and 11:08-11:11 after the restart. eb810c2 makes delegated runs drop teams_policy through profiles.APP_MODE_ONLY_COLLECTORS and allow-lists the certificate token call. The two operations that remain named skips are messagingPolicies (Get-CsTeamsMessagingPolicy) and appSetupPolicies (Get-CsTeamsAppSetupPolicy). TEAMS_READ_PATHS has no REST path for them and no adapter runs a Teams PowerShell session, so they record teams_powershell_not_supported. No row depends on them, so A1 closes all 11 rows: MS.TEAMS 1.1-1.7, 2.1-2.3 and 4.1. Nothing passes to M08-T04.
changes: commit eb810c2: src/azure_tenant_audit/selection.py:6,30; src/azure_tenant_audit/run.py:17,106,111; tests/test_http_verb_allowlist.py:172 (GraphClient._certificate_exchange -> app.acquire_token_for_client, TOKEN_POST, rows A1, A2); tests/test_presets.py:230 (delegated drop asserted)
verification: pytest verify set plus test_http_verb_allowlist and test_setup_guide pass on eb810c2; make lint pass on eb810c2 (both in the cut-off run, not repeated). make contract-smoke not run: host sitting. Evidence in .plan/work/M08-T01/evidence.md "Round 2".
risks: 1) The smoke is still owed on eb810c2 once the sitting clears. 2) Entra has not yet been shown to accept a live certificate token; M08-T06 tests that.
questions_for_g: none
### Findings
- Skips: src/azure_tenant_audit/adapters/teams_admin_rest.py:22-28 (no REST path); src/azure_tenant_audit/collectors/teams_policy.py:121-129 (named skip, no unauthenticated cmdlet)
- Rows and the operations they cite (configs/scuba-policy-sections.json): 1.1-1.6 meetingPolicies, 1.7 broadcastPolicies, 2.1-2.3 tenantFederationConfiguration, 4.1 clientConfiguration. No MS.TEAMS row cites a messaging or app-setup section. 5.1-5.3 fall outside A1's 11.
