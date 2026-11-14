## RESULT REV-RAPP-sol
status: done
summary: verdict: changes-required
reviewed: d5e9fe6249be
Both scripts and the record pass items 1, 2 and 4. Neither script has a consent path any more, and they add no new write and expose no secret. Only item 3 fails. The paths and the secret containment in PHASE-E-COMMANDS.md are correct, but its E7 expected lines are still the r1 lines. This needs a doc edit only, no script change. Detail: .plan/work/REV-RAPP-sol/recheck-3.md
changes: .plan/work/REV-RAPP-sol/recheck-3.md and progress.md only
verification: read-only. I read every named file in full, plus the r1-to-r2 diffs in RAPP-fix/evidence.md. I ran shasum on the three files: all match. Grep found no AllowConsent, -Scopes or grant write. Nothing was run, with no sign-in and no network.
risks: a .default consent screen is still possible, and only the operator pressing Cancel prevents it; READER-APP-RECORD.md L29 and phaseE/COMMANDS.md still describe the old phase E paths (no leak)
questions_for_g: none
### Findings
1 B1 pass: dt-live/create-auditex-reader-app.ps1:276-279 and dt-live/remove-auditex-reader-app.ps1:171-174 sign in without -Scopes and print the Cancel instruction first. A missing scope refuses at create:286-290 and remove:179-180, before any tenant write.
2 fixes pass: S3 at create:36-39 and remove:22-24; S4 at create:277,289; S5 and S6 at create:378-387, with the preflight PIM probe at create:300-301. Codex 17 is the Get-All helper at create:181-193 and remove:100-112. Codex 18 is at remove:259-271, before the first DELETE at remove:275. Writes are unchanged and all come after the intent entry: create:334 and remove:271.
3 fail: dt-live/phaseE/PHASE-E-COMMANDS.md:96 omits the sign-in line printed at create:277 and cuts the Global Reader line from create:389, which ends "and it holds no PIM eligibility". Fix: copy READER-APP-RECORD.md:14-18. The paths at L41-42 and the containment at L50, L111-119 and L285 pass.
4 pass: sha256 checked for the create script, the removal script and READER-APP-RECORD.md; all three match RAPP-fix result.md.
