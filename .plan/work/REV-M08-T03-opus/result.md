## RESULT REV-M08-T03-opus
status: done
summary: verdict: ship - all five repair items pass and no new blocking defect was found; the files match the new manifest 9/9. Three non-blocking notes are in .plan/work/REV-M08-T03-opus/notes.md (Round 2).
reviewed: f37ffb67a06a
changes: .plan/work/REV-M08-T03-opus/notes.md (Round 2 section added), progress.md
verification: shasum -a 256 -c MANIFEST.sha256: pass (9/9); nothing else run (read-only brief: no PowerShell, network or tenant)
risks: (1) The portal check compares a journal snapshot that went through JSON with a live read; a serialisation difference stops it safely with status failed. (2) The Fabric admin read and the portal read-back are still unproven on a live tenant.
questions_for_g: none
### Findings
1 pass: both routes verify the Fabric admin authority and that the setting is off with no groups, and journal both, before any write (create-m08b-pbi-access.ps1:137-163). An enabled setting refuses, so no group is created (:143-145).
2 pass: all eight settings are required, and every field is compared on both routes (m08b-common.ps1:365-385; create-m08b-pbi-access.ps1:146,211-212,65,74-76,84). Missing evidence refuses.
3 pass: a missing group id refuses with no name or time lookup (remove-m08b-pbi-access.ps1:43-51). Restore needs current ownership and a re-read before the step (:80-82,104-105) and a read-back (:113-118). Status removed is written only at :133 (RECORD.md:93).
4 pass: RECORD.md:22-24,86-87,110-117 and create-m08b-pp-mgmtapp.ps1:18-20 say register immediately before the power_platform collection and remove straight after it.
5 pass: .plan/work/M08-T03/draft/collector-post.patch:39 uses api-version 2020-10-01, and :259 pins it.
