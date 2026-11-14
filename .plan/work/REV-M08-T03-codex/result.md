## RESULT REV-M08-T03-codex
status: done
summary: verdict: do-not-ship; blocking rollback paths can disable shared access or delete an unrelated group.
reviewed: 1960baf8e177
changes: none
verification: SHA-256 manifest and all nine files PASS, including final recheck; static review completed; PowerShell, network and tenant checks excluded as instructed; progress file skipped because sandbox is read-only.
risks: DEC-060 operator-Cancel limit remains; draft listTenantSettings api-version lacks documented support.
questions_for_g: none
### Findings
1 FAIL: dt-live/m08-b/create-m08b-pbi-access.ps1:126 bypasses the setting precondition with -Portal, then :155 creates a group even when the setting is already enabled. Fix: refuse -Portal before writes until the disabled/no-groups baseline and required authority are verified and journalled. Explicit API writes otherwise follow intent; the stated DEC-060 consent limit is acknowledged.
2 FAIL: dt-live/m08-b/RECORD.md:38 confirms Portal skips kit snapshots; create-m08b-pbi-access.ps1:49 also accepts missing watched settings as null. Fix: require all eight settings, capture and compare their complete scope before/after on both routes, and refuse unavailable evidence. The target name and Power BI permission exclusions are correct.
3 FAIL (non-blocking): dt-live/m08-b/create-m08b-pp-mgmtapp.ps1:14 and RECORD.md:74 plainly disclose administrator-equivalent read/write access and prompt removal, but RECORD.md:18 says only “before” collection. Fix: explicitly require registration immediately before the collection needing it and removal straight after.
4 FAIL (blocking): dt-live/m08-b/remove-m08b-pbi-access.ps1:54 adopts a group by name/time, allowing :132 to delete another creator’s group; :87 and :124 instruct unconditional portal disabling without checking widened access. Fix: refuse missing journalled IDs pending manual reconciliation; require verified current setting ownership and read-back before restoration or status removed. Update RECORD.md:84 accordingly. Power Platform removal journals its DELETE and end state.
5 PASS: .plan/work/M08-T03/evidence.md:7 and :36 contain primary-source excerpts supporting AllowServicePrincipalsUseReadAdminAPIs and body-free POST. Version flag: management scripts use documented 2020-10-01 (dt-live/m08-b/create-m08b-pp-mgmtapp.ps1:28); draft/collector-post.patch:18 retains 2023-06-01 for listTenantSettings, whereas the cited documentation shows 2020-10-01. Sources were assessed offline.
6 PASS: dt-live/m08-b/m08b-common.ps1:283 reads the existing reader secret only after the mode-600 check; credentials are used in memory, with no explicit secret output or persistence. The production request paths read administrative metadata, never tenant message bodies or file content.
