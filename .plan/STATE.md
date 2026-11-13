# STATE
<!-- The only file read at every session start. Max 40 lines. Rewritten by checkpoint.sh and by small edits. -->
overall: 63% (was 61%)
milestone: M03-explainer-training 20%
plan_version: v4
release_scope: 1.5.0 (wider Ruff set, contract-test and gate-doc fixes, keyed per-run D5 pseudonyms plus middle initials and titles, v3 DEC-008/009 scanner follow-ups, review follow-ups, microsoft-skills deletion gate, signed tag plus GitHub release on G's yes naming 1.5.0) beside Track B (explainer model research on Isambard-AI to a judged build and G's pick, stage caps inside the 20,000 GPU-hour allocation per DEC-002; no model in 1.5.0)
last_checkpoint: f558abe 2026-11-13T23:42:14Z

## Next tasks
- M03-T02 Train three seeds of the chosen base on data v2 (terra)
- M03-T03 Build, hash and judge the final explainer build (terra)
- M03-T04 Write the recommendation and the product-integration options (sol)

## Blockers
- Host: QUIET WINDOW since about 23:10 GMT on 13 Nov (manager): start nothing that takes a heavy slot (merge wrapper, executing check, full suite) until the manager releases. Cluster jobs, Codex reviews and docs work go on. Otherwise heavy work goes through hostload.sh with PLAN_LOAD_MAX=12.
- Track A: M04-T04 is merged (8a72e59; DEC-039, DEC-042, DEC-044: no further author round, ever). The Claude privacy review of the merged head d7b4424 (REV-M04-T04-privacy) is owed by the milestone and running; the push is held until it reports; what it finds becomes a stated limit in M04-T05 unless it is a plain name in a common form (manager). Next: M04-T05 short run (note in work/M04-T05/fix-after-merge.md, plus every stated limit in BACKLOG), its re-check and merge; then M05-T04, M06-T01 and the M06 gates. Codex seats may run to 98 per cent (DEC-041); Codex authors here run pytest only (DEC-043 did not unblock lint).
- Track B: pilot attempt 1 missed (6 both-order wins of 190, 139 needed; filtered preference 0.5112). Attempt 2, the one allowed revision and the last, is running (M03-T06). Its result goes to the manager as one message; a fail stops the round and is G's choice (revisit rule 2 or park), taken to him by the manager. GPU-hours: basecmp 235.67 of 1,024, large 2.78 of 2,048, dataround 2.70 of 160.

## Pending G decisions
- Questions go to the team-manager chat with a recommendation and an evidence path, never to G here (DEC-036); its rulings and relayed words count as his. It wants messages only for decisions, blockers, G's hands or eyes, reserved actions and results it asked for.
- Phase D: kit 7r is accepted (manifest 510f26e348fd). The manager asks G for a slot and opens the tenant chat (start it in this checkout, no worktree, no /plan); nothing moves there until it says so.
- For the plan tooling owner (clean-dev), no decision: Codex sandboxes route the bytecode cache differently from the dispatching shell; milestone tags M00 to M03 exist from plan v2, so plan v4 milestones cannot be tagged; RETRO-M02 proposes a footer rule for runs over two hours.

## Re-baselines
- from 100% (plan v3 closed at 1.4.0) to 4% (plan v4 scope and weights, DEC-001, approved by G on 11 Nov 2026)
- from 13% to 12% (plan amendment 1: M00-T06 and one new M00 item for the as-of date, DEC-005)
- from 36% to 35% (plan amendment 2: milestone M07 at weight 12, M02-T06, new weights; DEC-018)
- from 53% to 52% (plan amendment 3: the data round adds two M03 items, the pilot and data v2; DEC-037)

## Quota snapshot
<!-- quota:begin -->
claude 45% orchestrator
claude-1 71% ok
claude-2 49% shared
claude-3 67% ok
claude-4 30% ok
claude-5 75% ok
codex 92% hot
codex2 87% hot
<!-- quota:end -->
