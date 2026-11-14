## RESULT RAPP-limit
status: done
summary: Both script headers now carry a "STATED LIMIT (DEC-060)" paragraph in the record's words, comment lines only. The parser shows the code unchanged. E7 opens with the bold Cancel sentence. Neither script was run, and there was no sign-in, network or tenant access.
changes: dt-live/create-auditex-reader-app.ps1, dt-live/remove-auditex-reader-app.ps1, dt-live/phaseE/PHASE-E-COMMANDS.md (READER-APP-RECORD.md read only, unchanged). Evidence: .plan/work/RAPP-limit/evidence.md
verification: PowerShell parser through the kit's guard copy, old against new, pass (both versions 0 errors; token streams identical once Comment and NewLine tokens are removed; text diff adds only `#` lines). Old copies matched the reviewed hashes before editing.
risks: none
questions_for_g: none
### Findings
1. Task 1: the paragraph is in both headers, taken from the record's "Stated limit" section (I added a "(DEC-060, accepted by the manager)" label and dropped nothing). 5 comment lines were added to create, 4 to remove, and nothing else changed.
2. Task 2: parse errors 0 in old and new. Non-comment token streams are identical for both scripts. NewLine tokens rose by exactly the number of comment lines added (5 and 4).
3. Task 3: E7 starts with the bold line "A permissions page here means Cancel, then tell the session." on its own line. No line in the file tells the operator to accept a permissions page.
4. Task 4: the hashes of the four files are below.
create-sha256: 77bb50cc1c6d45ef95ee370b0ec314badd2017ec895e035b6794a619bf718829
remove-sha256: 8d53d5d30576b107f79c267c5312fd1d59ab9168a78d4e0e177484ba55b0e831
record-sha256: 900e7e654aa47bdafba9c9a3eaa99ed37f30b2b5f38a292c05eb4af17b6c9122
phaseE-commands-sha256: 71439ebe409233ccdba62f776f1ce1f71567edc442acf4c48657251b3c8c1760
