## RESULT M08-T03
status: done
summary: Get-M8TenantSettings now accepts the two-list reply only when both lists match on count, settingName set and `enabled` for each setting. It then reads `tenantSettings`; any difference refuses, one list alone works as before, and neither still refuses. By default the Fabric mock now answers with both lists. Seven new cases were added and the harness passes 69/69. Re-frozen, with MANIFEST-2.sha256 kept. Details: .plan/work/M08-T03/notes.md, "Repair round 2".
changes: dt-live/m08-b (m08b-common.ps1, tests/mock.ps1, tests/run-tests.ps1, RECORD.md, MANIFEST.sha256, new MANIFEST-2.sha256); .plan/work/M08-T03 (notes.md, progress.md)
verification: harness through kit-7r pwsh-guarded 69/69: pass; new harness against the f37ffb67a06a copy: 30 fail, including the equal-lists case ("neither or both"): fails as expected; parse through pwsh-guarded, 8 files, 0 errors: pass; new manifest check, 0 mismatches: pass
risks: (1) Not tried on a live tenant; the Power BI reader read uses the same rule. (2) A setting name repeated within one list now refuses. (3) The harness work folder must be on the internal disk because of the scripts' preflight.
questions_for_g: none
### Findings
fix: m08b-common.ps1:316-318 (helper :326-340)
new-cases: 7 fail-on-previous 5
harness: pass 69/69
changed-files: RECORD.md, m08b-common.ps1, tests/mock.ps1, tests/run-tests.ps1
frozen: b02012a51eb7
pbpp-check: EXP-m08-pbpp
pbi-readonly-admin-setting: AllowServicePrincipalsUseReadAdminAPIs
pp-tenant-settings-method: POST
removal-step: present
expected-verdicts-changed: 0
