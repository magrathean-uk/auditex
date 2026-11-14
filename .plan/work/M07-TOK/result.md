## RESULT M07-TOK
status: done
summary: Items 1, 2a, 2b and 5 are fixed in sitting-tokens.ps1 (r1) and its harness, with one re-freeze. Each token's scp must now hold the scope the kit's request gets and nothing outside that set; a missing scope or an extra grant refuses. Every token is re-checked immediately before publication. The run is one try/finally that publishes all or nothing and unsets every requested variable if it does not complete. The header states limits 3 and 4. No sign-in, tenant or network was used and the kit was not edited. Details are in .plan/work/M07-TOK/notes.md.
changes: dt-live/phaseD/sitting-tokens.ps1, dt-live/phaseD/sitting-tokens-tests/{driver,mock,run-tests}.ps1, dt-live/phaseD/MANIFEST.sha256 (new), dt-live/phaseD/MANIFEST-1.sha256 (r0 kept), all in the records folder
verification: parse.ps1 on the helper and the test files: pass, 0 errors; run-tests.ps1 through the kit's pwsh-guarded: pass 40/40; four mutation checks (no re-check, no finally clear, no allowed-scope check, no needed-scope check) each fail 1 to 3 tests as intended; shasum -a 256 -c MANIFEST.sha256: pass 5/5
risks: The expected scp sets for spo, pbi and pp are not observed live for those exact tokens; a wrong guess refuses and never accepts more. r1 has not had an independent re-review yet.
questions_for_g: none
### Findings
fix: 1 dt-live/phaseD/sitting-tokens.ps1:133
fix: 2a dt-live/phaseD/sitting-tokens.ps1:263
fix: 2b dt-live/phaseD/sitting-tokens.ps1:229
fix: 5 dt-live/phaseD/sitting-tokens-tests/run-tests.ps1:114
harness: pass 40/40
frozen: e46247d398c9
stated-limits: 3, 4 (DEC-060)
