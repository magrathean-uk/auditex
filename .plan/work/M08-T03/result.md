## RESULT M08-T03
status: done
summary: New shared Get-M8SettingList in m08b-common.ps1 applies the fix-2 rule; Get-M8TenantSettings and the update answer in create-m08b-pbi-access.ps1 both use it. The removal script ignores the update answer and the Power Platform checks use a different API, so no other envelope reads exist. A refused update answer follows the existing failure path: the journal is marked failed and the removal script can undo the run. The harness was offered to hostload twice and deferred both times (both slots held), so it ran directly at low priority as a light mock run, about 3 minutes.
changes: kit m08-b folder (m08b-common.ps1, create-m08b-pbi-access.ps1, tests/mock.ps1, tests/run-tests.ps1, new MANIFEST.sha256, MANIFEST-3.sha256 kept); .plan/work/M08-T03 (notes.md, progress.md, harness-3-new.txt, harness-3-prev.txt)
verification: parse through kit-7r pwsh-guarded 8 files 0 errors pass; mock harness 79/79 pass; previous scripts with new tests 74/79 (5 new checks fail, as intended); shasum -c against new manifest pass; repository git status clean
risks: runtime untested against a live update answer (mock only)
questions_for_g: none
### Findings
fix: m08b-common.ps1:323 (Get-M8SettingList), called at m08b-common.ps1:316 and create-m08b-pbi-access.ps1:202
new-cases: 10 fail-on-previous 5
harness: pass 79/79
changed-files: m08b-common.ps1, create-m08b-pbi-access.ps1, tests/mock.ps1, tests/run-tests.ps1 (RECORD.md, three other scripts, tests/parse.ps1 hash-identical)
frozen: 96aee184809c
pbpp-check: EXP-m08-pbpp
pbi-readonly-admin-setting: AllowServicePrincipalsUseReadAdminAPIs
pp-tenant-settings-method: POST
removal-step: present
out-of-kit-row: written
expected-verdicts-changed: 0
