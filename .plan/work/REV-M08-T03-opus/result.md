## RESULT REV-M08-T03-opus
status: done
summary: verdict: ship
reviewed: 521703f2826d
changes: none in the kit; only my review notes, at .plan/work/REV-M08-T03-opus/notes-6.md and progress.md
verification: all 9 files match the hashes in MANIFEST.sha256 (pass); a full diff of the removal script against a byte copy of the previous version (pass); mock and RECORD.md compared with the round-4 copy (pass). Harness not run because the brief forbids PowerShell.
risks: I found no byte copy of the previous mock, run-tests or RECORD.md, so I judged those by content. If the group stays live past 5 minutes and then vanishes, the run stops at the first absent read without watching deleted items any longer (remove:198). It journals "not seen", so a re-run picks it up.
questions_for_g: none
### Findings
1: remove:193-199 reads the live group and deleted items on every poll, 15 s apart. A sighting is checked (:201), purged and read back absent from both (:53-61). Not live and never seen after 5 minutes means removed with deleted-items: not seen in 5 min (:206-208).
2: remove:68-97 re-runs over a removed journal with the Graph sign-in only, by the journalled id. A plan run writes nothing. A refusal keeps the status removed. With -Apply it adds a recheck-deleted-items removals entry, purges and journals removed.
3: mock:92-93 adds a late deleted item (default off, run-tests:36). run-tests goes from 59 to 65 checks; the 6 new ones (:259-293) cover the late purge, never seen, re-check plan and apply, nothing to do, and a wrong-name refusal.
4: No check is weaker; the temp-file refusal now also guards the removed path. Only the four files the manifests list changed, and RECORD.md only in its text at line 73.
