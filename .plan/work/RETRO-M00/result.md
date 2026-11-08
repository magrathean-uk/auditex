## RESULT RETRO-M00
status: done
summary: 31 M00-related ledger rows (incl. VAL-v2 and RETRO-M02, which name M00 tasks): 31 runs, 3.1244 USD recorded (10 rows blank, Codex launches), 6805 s, 13 non-zero exits (1 timeout, 11 partial, 1 blocked).
summary: M00-T01 ledger ends blocked at 19c7ea7 while result.md says partial; M00-T02 has no done row yet the milestone table says done. Both recorded as found, not reconciled.
summary: Brief fixes are backed by M00 failures; the footer rules (single RESULT keys, no doctor, linked .venv) already exist and postdate most M00 writer runs.
changes: .plan/RETRO.md (appended "## M00" only, 51 additions, 0 deletions); .plan/work/RETRO-M00/notes.md; .plan/work/RETRO-M00/evidence.md
verification: ledger aggregation with python3 (12 columns on every row, no malformed rows): pass; git diff --numstat .plan/RETRO.md: pass (additions only); no commit made.
risks: Cause of 7 of 11 partial exits and the M00-T01 timeout is not recorded in ledger or result.md, so not attributed; the M00-T01 done/blocked rows conflict.
risks: Codex-launched rows carry no cost, so the spend total is a floor, not a full figure.
risks: The SessionStart hook reported clean-development lifecycle registration failure and asked for a doctor run; the brief forbids it, so I did not run it. G to decide.
questions_for_g: none
### Findings
- luna-explore.md: make the final reply the RESULT block itself; send long notes to the work dir (M00-T01 filed by orchestrator, no RESULT block).
- codex-implement.md: on partial exit, write one cause line in the RESULT summary (M00-T02, T03, T05 exit 1 with no recorded cause).
- codex-implement.md and terra-implement.md: no keys beyond the RESULT contract, no repeated summary lines or dispatch key (M00-T02).
