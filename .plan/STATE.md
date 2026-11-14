# STATE
<!-- The only file read at every session start. Max 40 lines. Rewritten by checkpoint.sh and by small edits. -->
overall: 69% (was 70%)
milestone: M03-explainer-training 20%
plan_version: v4
release_scope: 1.5.0 (wider Ruff set, contract-test and gate-doc fixes, keyed per-run D5 pseudonyms plus middle initials and titles, v3 DEC-008/009 scanner follow-ups, review follow-ups, microsoft-skills deletion gate, signed tag plus GitHub release on G's yes naming 1.5.0) beside Track B (explainer model research on Isambard-AI to a judged build and G's pick, stage caps inside the 20,000 GPU-hour allocation per DEC-002; no model in 1.5.0)
last_checkpoint: 6ddef18 2026-11-14T10:54:57Z

## Next tasks
- M03-T02 Train three seeds of the chosen base on data v2 (terra)
- M03-T03 Build, hash and judge the final explainer build (terra)
- M03-T04 Write the recommendation and the product-integration options (sol)

## Blockers
- Host (manager 09:26 GMT): sitting file `last` step 4 or lower and stopped null: heavy jobs through the slot (PLAN_LOAD_MAX=12) except VM boots and runs over 30 min (not the full kit suite); step 5 on or paused: no heavy start. No live tenant runs.
- Track A: 1.5.0 is RELEASED and verified (DEC-052; M06 complete): tag v1.5.0 on a1c6b5e; https://github.com/magrathean-uk/auditex/releases/tag/v1.5.0 (wheel 81ea5c2f..., sdist 959e825f...). Track A reopens only for M08 collection completeness (DEC-059; amendment 5 merged).
- Track B: stopped and on hold (DEC-053, G on 14 Nov: "master data collection etc first ... talk about training AFTER"). The pilot failed (M03-T06: 18 wins of 190, 139 needed; 5.57 GPU-hours). Nothing in M03 moves; amendment 4 (parked case) stays unmerged at bf19a3f. Training is discussed again after phase D. GPU-hours used: about 306 of 20,000.

## Pending G decisions
- Approval channel: G in this chat (DEC-063, 14 Nov 10:22 GMT; the manager and tenant chats were archived about 10:07 GMT). DEC-036 to DEC-062 rulings stay.
- Live (DEC-064): reader app created 10:31 GMT (row 8; rollback line in .plan/work/M07-T17/manual-stops.md). pre-d collection: partial, 66 of 102 not assessed vs 35 expected; EXP-m07-pred-gaps maps the 31 extra to permission, defect, tenant or input. Lab Fabric app (DEC-066) being scripted.
- Phase D (M07): STOPPED at its first look-up, no tenant write (Graph 404 with a null StatusCode; dt-live/phaseD/FAULT-7r-notfound.md). Round 7s (DEC-054): part 1 candidate kit/20261111-kit-7s/dt-r7s-cand d453c83ac710 (368 files) sent to the manager 09:33 GMT for read-only dry runs (wait for the network-hold lift); part 2a done (compare.py reads 1.5.0: rc 0, 0 malformed; result-2a.md; its E11 gate line goes into PHASE-E-COMMANDS.md with the 7s hand-over); part 2b folds dry-run findings; then the gate (both providers, full suite 9 of 9), freeze 7s, new hand-over. M07-T15 held.

## Re-baselines
- from 100% (plan v3 closed at 1.4.0) to 4% (plan v4 scope and weights, DEC-001, approved by G on 11 Nov 2026)
- 13% to 12% (amendment 1, DEC-005); 36% to 35% (amendment 2: M07 at weight 12, M02-T06; DEC-018)
- 53% to 52% (amendment 3, DEC-037); 63% to 62% (M04-T06 added, DEC-045); 64% to 65% (M04-T06 stopped, DEC-048)
- 84% to 70% (amendment 5: M08 at weight 14, others scaled; DEC-059, G via manager; fbce88f); 70% to 69% (amendment 6: round 7s and the Fabric app in M07; DEC-054, DEC-066; 6ddef18)

## Quota snapshot
<!-- quota:begin -->
claude 60% orchestrator
claude-1 75% ok
claude-2 50% shared
claude-3 71% ok
claude-4 44% ok
claude-5 78% ok
codex 94% hot
codex2 90% hot
<!-- quota:end -->
