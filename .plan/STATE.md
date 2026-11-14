# STATE
<!-- The only file read at every session start. Max 40 lines. Rewritten by checkpoint.sh and by small edits. -->
overall: 64% (was 62%)
milestone: M03-explainer-training 20%
plan_version: v4
release_scope: 1.5.0 (wider Ruff set, contract-test and gate-doc fixes, keyed per-run D5 pseudonyms plus middle initials and titles, v3 DEC-008/009 scanner follow-ups, review follow-ups, microsoft-skills deletion gate, signed tag plus GitHub release on G's yes naming 1.5.0) beside Track B (explainer model research on Isambard-AI to a judged build and G's pick, stage caps inside the 20,000 GPU-hour allocation per DEC-002; no model in 1.5.0)
last_checkpoint: 9219099 2026-11-14T00:09:12Z

## Next tasks
- M03-T02 Train three seeds of the chosen base on data v2 (terra)
- M03-T03 Build, hash and judge the final explainer build (terra)
- M03-T04 Write the recommendation and the product-integration options (sol)

## Blockers
- Host: quiet window until 00:30 GMT on 14 Nov (manager): until then nothing that takes a heavy slot. From 00:30 GMT heavy steps run again under the usual rule: one heavy slot through hostload.sh, load 12 or less (PLAN_LOAD_MAX=12).
- Track A: M04-T04 (8a72e59, both providers approve the merged head; no further author round, ever) and M04-T05 (afa6308, docs with ten stated limits) are merged. M04-T06 (DEC-045: withhold only the line or cell in rendered output, count it in the note) is with its author (sol, no heavy slot); then REV-M04-T06 by Codex, one repair, one re-check, then a choice to the manager; its executing check, a short doc follow-up and its merge wait for the release. Then M05-T04, M06-T01 and the M06 gates. Codex seats may run to 98 per cent (DEC-041); Codex authors here run pytest only.
- Track B: the pilot FAILED and the data round has stopped (M03-T06 done, verified: attempt 1 6 wins of 190, attempt 2 18 of 190, 139 needed; filtered preference 0.5112 then 0.5337 against 0.729; unfiltered losses rose from 42 to 73). M03-T07, M03-T02 and M03-T03 do not run. The choice (revisit rule 2 of the bar, or park the model track) is G's, taken to him by the manager; nothing in M03 moves before his answer (he is back at 07:00 GMT on 14 Nov; the manager recommends parking, as I do). Amendment 4 for the parked case is being prepared as AMEND-4 and is not merged without his words (DEC-046). GPU-hours: basecmp 235.67 of 1,024, large 2.78 of 2,048, dataround 5.57 of 160.

## Pending G decisions
- Questions go to the team-manager chat with a recommendation and an evidence path, never to G here (DEC-036); its rulings and relayed words count as his. It wants messages only for decisions, blockers, G's hands or eyes, reserved actions and results it asked for.
- Phase D: kit 7r is accepted (manifest 510f26e348fd). The manager asks G for a slot and opens the tenant chat (start it in this checkout, no worktree, no /plan); nothing moves there until it says so.

## Re-baselines
- from 100% (plan v3 closed at 1.4.0) to 4% (plan v4 scope and weights, DEC-001, approved by G on 11 Nov 2026)
- from 13% to 12% (plan amendment 1: M00-T06 and one new M00 item for the as-of date, DEC-005)
- from 36% to 35% (plan amendment 2: milestone M07 at weight 12, M02-T06, new weights; DEC-018)
- from 53% to 52% (plan amendment 3: the data round adds two M03 items, the pilot and data v2; DEC-037)
- from 63% to 62% (new task M04-T06 and one M04 item: the withholding reach in rendered output; DEC-045)

## Quota snapshot
<!-- quota:begin -->
claude 46% orchestrator
claude-1 71% ok
claude-2 49% shared
claude-3 67% ok
claude-4 32% ok
claude-5 75% ok
codex 92% hot
codex2 87% hot
<!-- quota:end -->
