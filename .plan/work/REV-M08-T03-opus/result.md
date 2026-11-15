## RESULT REV-M08-T03-opus
status: done
summary: verdict: ship
reviewed: 947405dfecfc
changes: none in the kit; review notes in .plan/work/REV-M08-T03-opus/notes-8.md and progress.md
verification: all 9 files match MANIFEST.sha256 (pass). Compared with MANIFEST-7, only common, create, mock, run-tests and RECORD.md changed; remove, the pp scripts and parse.ps1 are the same (pass). I did not run the harness because the brief forbids PowerShell.
risks: A 400 that is a real error, not group lag, now takes about 7.5 minutes of identical sends before the run stops. The run still fails safe. There is no byte copy of the previous files, so I judged the unchanged regions by their content.
questions_for_g: none
### Findings
1: create:229-241 builds the body once and journals it before the loop. The loop re-sends the same POST, but only on a 400 (Get-M8Status reads the status that Invoke-M8Api stores, common:188-195). It sends at most 16 times, 30 s apart (common:222-225), and records setting.update400s each time. Any other status, or a transport error (status 0), stops the run at once. No new host, path or scope.
2: The answer check, the read-back and the kit-settings comparison at create:242-255 are unchanged. If the 400 never clears, the outer catch marks the journal failed at enable-setting. The removal treats that as touched (remove:102) and restores the setting only when it reads ours (remove:144).
3: mock:130-131 answers 400 before changing any state, and every send is logged first (mock:31). PBI 15c (run-tests:232-246) checks two cases. 400 twice then 200: three sends and the run completes. 400 for good: 16 sends, the run fails, the setting stays unchanged and the removal completes. RECORD.md:73 adds one sentence.
