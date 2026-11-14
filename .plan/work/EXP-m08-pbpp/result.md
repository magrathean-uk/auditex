## RESULT EXP-m08-pbpp
status: done
summary: Enabling `power_bi` and `power_platform` needs three tenant changes: a security group, one Power BI admin setting, and a Power Platform management-app registration. None touches a verdict the kit expects. The break-glass variant is irrelevant here. Product limits, not tenant changes, keep PP 3.1 and 2.3 not assessed and put four PP rows at risk. At most 14 of the 16 rows can close.
changes: none (notes in .plan/work/EXP-m08-pbpp/notes.md)
verification: none; read-only review
risks: (1) The API settingName of the Power BI read-only admin API setting is in neither the repository nor the kit, so I could not check it offline. Confirm it is not the MS.POWERBI.4.1 toggle `ServicePrincipalAccessPermissionAPIs`. (2) The product pins GET for `listTenantSettings` (src/azure_tenant_audit/collectors/power_platform.py:20,86) but the kit uses POST (kit/populate/70-powerplatform.ps1:29), so PP 1.1, 1.2, 5.1 and 6.1 may stay not assessed. (3) The management-app registration is a write with unknown blast radius (docs/guides/admin-permission-guide.md:329-331).
questions_for_g: none
### Findings
- Q1 power_bi: client-credentials token for the Power BI scope (src/azure_tenant_audit/power_bi.py:13,26; graph.py:335-345), one GET of /v1/admin/tenantsettings (collectors/power_bi.py:11,52). It needs no API permission (configs/collector-permissions.json:228-233).
- Q1 power_bi tenant side: a plain Entra security group holding only the reader's service principal, and the admin-portal setting "Service principals can access read-only admin APIs" enabled for that group (docs/guides/admin-permission-guide.md:311-318).
- Q1 power_bi licence: a Power BI plan must show in the licensing evidence (src/auditex/scuba_adapters_powerplat.py:13,66-68; value_rules/powerbi.py:33-41). The kit assumes Power BI is licensed (kit/EXPECTED-VERDICTS.json assumptions).
- Q1 power_platform: token for `https://service.powerapps.com//.default` (power_platform.py:13,40) and six GET endpoints (collectors/power_platform.py:21-25). It needs a one-time `New-PowerAppManagementApp -ApplicationId <reader app>` after `Add-PowerAppsAccount`, run by a Power Platform admin or global admin (docs:323-331).
- Q1 power_platform extras: no new Graph permission. tenantIsolation also reads Graph /organization with the existing Directory.Read.All (collectors/power_platform.py:101-111). Both collectors are opt-in through the `power-platform` preset (configs/collector-presets.json:69-75).
- Q2 change (a), group plus service principal membership: touches an expected verdict: no. No non-Power rule's deciding setting is a group, and the kit's own four groups are untouched (kit/BLUEPRINT.md:67).
- Q2 change (b), read-only admin API setting: touches an expected verdict: no. The kit converges only eight named settings (kit/populate/60-powerbi.ps1:82-91), none of them this one. Rules match on exact settingName (value_rules/powerbi.py:53), and an extra list entry is ignored (60-powerbi.ps1:48-53).
- Q2 change (c), management-app registration: touches an expected verdict: no. The kit's step 70 sets four flags, one DLP policy and isolation (kit/populate/70-powerplatform.ps1:51-56,92,115), and no rule reads app registrations.
- Q2 expected verdicts: PBI 1.1 not met, 2.1 met, 3.1 not met, 4.1 met, 4.2 not met, 5.1 met, 6.1 not met, 7.1 met. PP 1.1 met, 1.2 not met, 2.1 met, 2.2 met, 2.3 not met, 3.1 not met, 5.1 met, 6.1 not met.
- Q2 variants: every one of the 16 rows is identical with and without break-glass (kit/EXPECTED-VERDICTS.json:1582-1894 onward). The flag only matters for the AAD conditional-access rows.
- Q2 kit setters: 60-powerbi.ps1:83-90 and 70-powerplatform.ps1:52-55. PP 3.1 is left never configured (70:115-119). The pinned ScubaGear oracle gives PP 2.3 "met" and PP 3.1 no verdict (kit/BLUEPRINT.md:228-229,240).
- Q3: no change touches a verdict, so no workaround is needed. If the read-only admin setting turned out to share the 4.1 toggle, scoping it to the reader group keeps 4.1 met, because "enabled for listed groups" is met (value_rules/powerbi.py:87-89).
- Q3 trade-off: do not scope 4.2 to a group, because that would flip its expected "not met" to met (kit/BLUEPRINT.md:204). Switching the setting back after a separate run is possible but not needed. Leaving the rows not assessed is the fallback.
- Q3 product limits, independent of the tenant:
  - PP 3.1 stays not assessed. A never-configured tenant raises unavailable (scuba_adapters_powerplat.py:15,40-42), while the kit expects "not met".
  - PP 2.3 is a constant not-assessed rule (value_rules/power_platform.py:144-146; docs:365).
  - So at most 14 of the 16 rows can close.
- Q4: the kit's verify reads Power BI settings by the eight names only (kit/populate/90-verify.ps1:1026-1051). It reads Power Platform settings, DLP, environments and isolation (90-verify.ps1:1060-1110). It cannot see the group, the admin setting or the registration.
- Q4 ScubaGear: the cross-check selects powerbi and powerplatform (kit/scubagear-config.yaml:11-12) and reads the same named settings, so none of the three changes shows there either.
- Q5: go ahead with all three changes: none alters an expected verdict, and each gets a removal step and an OUT-OF-KIT-WRITES.md row.
- Q5 before the script: confirm the exact name of the read-only admin API setting is not `ServicePrincipalAccessPermissionAPIs`, and settle the GET versus POST question for `listTenantSettings`. Plan for 14 rows closed, not 16.
