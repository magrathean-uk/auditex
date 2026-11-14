## RESULT EXP-m07-pred-gaps
status: done
summary: Of the 66 not-assessed rows, 35 are the expected M rows. The other 31 are: 2 permission (P), 18 product defect (D), 9 tenant state that phase D creates (T), 2 operator input (I). AAD 3.4 is counted as D and closes after phase D. Two Graph read permissions are missing from the reader app and from every product doc and config. Five small product defects (D1-D5) plus the permission, the operator lists and phase D would close 25 of the 31. SPO 1.2, 2.1, 2.2, 3.1-3.3 need a SharePoint admin read that Graph does not provide (D6, size L). Two read-only offline runs of the product on the bundle confirmed that D1 decides AAD 3.3 and 3.5 (both not met), and D3 decides AAD 5.2 (not met).
changes: none in the repository; wrote .plan/work/EXP-m07-pred-gaps/notes.md and progress.md
verification: read the bundle, diagnostics, reader-app record, kit and product code; ran project_run plus value_rules.assess offline on the bundle with D1 and D3 patched in memory; both ran and gave the results above; no network, no tenant
risks: 1) The Graph sharepointSettings field list and the claim that an app-only SharePoint admin read needs Sites.FullControl.All were not re-checked online. 2) D2 alone may still hit throttling on the 149-policy fan-out; pacing may be needed too. 3) D5 reverses value-rule spec ruling D29 (lead's call).
questions_for_g: SPO 1.2, 2.1, 2.2, 3.1-3.3 can only be read from SharePoint admin settings. In app-only runs that probably needs the write-capable Sites.FullControl.All with a certificate. Choose one: accept these 6 rows staying not assessed in app-only runs, or build D6 using the single delegated sign-in only? I recommend the delegated path and no write-capable app permission.
### Findings
- M (35): TEAMS 1.1-1.7, 2.1-2.3, 4.1, 5.1-5.3; POWERBI 1.1-7.1; POWERPLATFORM 1.1-6.1; SS 3.1-3.4, 4.1. Already covered by EXP-m07-teams and EXP-m08-pbpp.
- P (SPO 1.1, 1.3): /admin/sharepoint/settings returned 403, and the client then stopped all calls to that endpoint family (src/azure_tenant_audit/collectors/sharepoint.py:22, sharepoint_access.py:99, onedrive_posture.py:47). Fix: SharePointTenantSettings.Read.All, plus D3.
- D (SPO 1.2, 2.1, 2.2, 3.1-3.3): Graph settings lack these rows' fields (ODB, default link type and permission, anonymous link expiry and type, email attestation) (docs/reference/output-contract.md:807). With the permission alone they still read field_absent. Fix: D6.
- D (AAD 3.3, 3.5): the collector calls a list endpoint Graph rejects (bad_request, src/azure_tenant_audit/collectors/auth_methods.py:27-33). The configurations already come inline in /policies/authenticationMethodsPolicy. The adapter also rejects the null policyMigrationState (src/auditex/scuba_adapters_aad.py:46). Fix: D1.
- D+T (AAD 3.4): after D1 the rule reads the null state as not assessed; phase D sets migrationComplete (kit populate/05-entra-settings.ps1:225-228).
- D (AAD 3.6, 7.4-7.9): 429s inside $batch responses are never retried (src/azure_tenant_audit/graph.py:780-873; only a top-level 429 is, at :557). roleManagementPolicyRules came back partial, so no privileged_roles artefact was written (src/auditex/scuba_projection.py:293-297). Fix: D2.
- D (AAD 5.2): the classifications read worked (8 rows), but the derived servicePrincipalFanout gap is not attributable, so the section is withheld (src/auditex/scuba_projection.py:304, 587-596). Fix: D3.
- T (AAD 5.3): no Consent Policy Settings directory setting yet; phase D creates it (05-entra-settings.ps1:106-125; BLUEPRINT.md:112).
- T (AAD 5.5-5.7): the default app management policy has no restrictions, so the rule reads entry_missing; phase D writes them (05-entra-settings.ps1:167-171; BLUEPRINT.md:113-115, 413).
- D (EXO 3.1): Get-DkimSigningConfig is not wrapped in `,@(...)`, so an empty answer is read as command_output_empty (src/azure_tenant_audit/collectors/exchange_policy.py:164; adapters/powershell_graph.py:333-339). Fix: D4. Phase D's custom-domain config also fills it.
- D (EXO 4.1-4.4): the DNS log shows NXDomain at every step of the DMARC lookup, but src/azure_tenant_audit/value_rules/dns.py:134-135 still treats an empty answer as unusable. The onmicrosoft domain keeps deciding these rows after phase D (BLUEPRINT.md:54-57). Fix: D5.
- T (EXO 7.1): no transport rule yet; phase D creates it (20-exchange.ps1:35).
- I (SS 2.1, 2.3): pass `--sensitive-users FILE` (the SensitiveUsers list in scubagear-config.yaml) and `--partner-domains FILE` (its PartnerDomains), or set AUDITEX_SENSITIVE_USERS_FILE and AUDITEX_PARTNER_DOMAINS_FILE (src/azure_tenant_audit/cli.py:254-255). The E8b command passed neither.
- Coverage gaps:
  - apps: D, a by-design budget limit (src/azure_tenant_audit/collectors/app_consent.py:25).
  - audit_logs: T, the reports service answers UnknownTenantId for this new tenant; no SCuBA row depends on it.
  - collaboration and data_exposure: P (settings); D7 (sitePermissions, sharepoint_access.py:132,229); a by-design 10-of-12 site limit; M (Teams token).
  - devices: P, DeviceManagementScripts.Read.All.
  - governance: D2.
  - identity: D1.
  - mail: M (protectionAlerts) and D4 (DKIM).
  - defender skip (not one of the 8 gaps): T, not provisioned on the trial; the two 504s were its Secure Score reads.
permissions-to-add:
- SharePointTenantSettings.Read.All: read-only. Tenant-wide SharePoint and OneDrive admin settings, no content.
- DeviceManagementScripts.Read.All: read-only. Intune script metadata and bodies, which can hold secrets; Auditex already drops the script body from its read (intune_depth.py:25).
- Do not add Sites.FullControl.All (write-capable).
product-defects:
- D1: size S, tier B. Files: collectors/auth_methods.py, scuba_adapters_aad.py:42-59.
- D2: size S-M, tier A (network). Files: graph.py:780-873.
- D3: size S, tier B. Files: scuba_projection.py:304.
- D4: size S, tier B. Files: exchange_policy.py:164.
- D5: size S-M, tier B. Files: value_rules/dns.py:130-140, plus vectors and rule packs.
- D6: size L, tier A. SharePoint admin read.
- D7: size S, tier B. Files: sharepoint_access.py:120-140,225-235.
docs-default-set-wrong: yes.
- configs/collector-permissions.json:198-226 lists only Sites.Read.All for the SharePoint collectors and omits SharePointTenantSettings.Read.All.
- configs/collector-permissions.json:367-378 omits DeviceManagementScripts.Read.All and says no new scope is needed.
- configs/collector-permissions.json:119 says the rejected list endpoint is read.
- docs/guides/admin-permission-guide.md:140-163 omits both new scopes and Sites.Read.All.
