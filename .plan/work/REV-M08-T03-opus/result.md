## RESULT REV-M08-T03-opus
status: done
summary: verdict: ship; the update answer and every list read now go through Get-M8SettingList (the fix-2 rule), a refusal there is journalled and the removal works; tests are added, none weakened. Notes: .plan/work/REV-M08-T03-opus/notes.md
reviewed: 96aee184809c
changes: none (review notes only, in .plan/work/REV-M08-T03-opus/)
verification: shasum -c MANIFEST.sha256 9/9 pass; manifest hashes 96aee184809c and b02012a51eb7 confirmed; read the code and the author's harness outputs (new 79/79, previous 74/79, all 5 failures new); scripts not run (read-only)
risks: no byte copy of the b02012a51eb7 files survives, so changes inside each file were checked by reading, not by a byte diff; runtime is mock-only
questions_for_g: none
### Findings
1 PASS: m08b-common.ps1:323-329 Get-M8SettingList holds the rule (via Assert-M8SameSettingLists :330-344) and is called by both reads, Get-M8TenantSettings :316 and the update answer at create-m08b-pbi-access.ps1:202. A refusal at :202 throws inside the try (:52) and reaches Save-M8Failure (:221). The update answer at remove-m08b-pbi-access.ps1:111 is thrown away and the setting is read again through Get-M8TenantSettings.
2 PASS: tests/mock.ps1:111-122 adds updateShape and keeps tenantSettings alone as the default. tests/run-tests.ps1:261-279 covers both lists, value alone, a count difference, a name difference, an enabled difference and neither list, each with the journal marked failed and the removal run. The 69 earlier checks remain (79 minus 10 new) and pass on the previous scripts.
3 PASS (file level): against MANIFEST-3 only m08b-common.ps1, create-m08b-pbi-access.ps1, tests/mock.ps1 and tests/run-tests.ps1 changed. The other 5 files, RECORD.md included, are hash-identical, and what changed inside the 4 files matches the author's account.
