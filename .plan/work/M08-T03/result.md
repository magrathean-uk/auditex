## RESULT M08-T03
status: done
summary: After the delete, the removal reads the live group and deleted items every 15 s and purges as soon as the group shows in deleted items. If it is not seen within 5 minutes of the delete, the journal ends `removed` with `deleted-items: not seen in 5 min`.
Re-running over a `removed` journal signs in to Graph only and re-checks deleted items for the journalled group id. With -Apply it purges and journals a `recheck-deleted-items` removals entry; it reads nothing else. A refusal there keeps the status `removed`.
The mock gains `binLag`, a deleted item that appears late. 7 new checks cover purge-in-run, not-seen, re-check plan/apply/again and a wrong-name refusal.
Kit re-frozen. MANIFEST-5.sha256 keeps 1e5e74938361. The live m08b-pbi.json is unchanged (hash f56e2830, mtime before this run). Details: .plan/work/M08-T03/notes.md.
changes: dt-live/m08-b (records, outside repo): remove-m08b-pbi-access.ps1, tests/mock.ps1, tests/run-tests.ps1, RECORD.md (one sentence on the watch and re-check), MANIFEST-5.sha256 (renamed), MANIFEST.sha256 (new)
verification: pwsh-guarded tests/run-tests.ps1 pass 94/94 (.plan/work/M08-T03/harness-5.txt); pwsh-guarded tests/parse.ps1 on the kit and tests/ pass, 0 errors; shasum of MANIFEST-5 = 1e5e74938361 pass
risks: The 5-minute window counts from the delete, so a group that stays live for a long time gets less watch time once it leaves groups; the re-check covers that case. In a work dir on the external volume the harness fails before any check runs, because the scripts refuse external volumes; it was run from an internal-disk work dir.
questions_for_g: none
### Findings
fix: remove-m08b-pbi-access.ps1:193 (5-min watch of groups and deleted items, purge on sight), :206 (not seen in 5 min journalled), :69 (re-check over removed, journalled id only)
harness: pass 94/94
changed-files: RECORD.md 56a3bba1, remove-m08b-pbi-access.ps1 a35bec5e, tests/mock.ps1 c96c1e76, tests/run-tests.ps1 3af052df
frozen: 521703f2826d
pbpp-check: EXP-m08-pbpp
pbi-readonly-admin-setting: AllowServicePrincipalsUseReadAdminAPIs
pp-tenant-settings-method: POST
removal-step: present
out-of-kit-row: written
expected-verdicts-changed: 0
