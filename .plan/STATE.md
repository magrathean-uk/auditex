# STATE
<!-- The only file read at every session start. Max 40 lines. Rewritten by checkpoint.sh and by small edits. -->
overall: 35% (was 36%)
milestone: M02-explainer-data-and-judging 50%
plan_version: v4
release_scope: 1.5.0 (wider Ruff set, contract-test and gate-doc fixes, keyed per-run D5 pseudonyms plus middle initials and titles, v3 DEC-008/009 scanner follow-ups, review follow-ups, microsoft-skills deletion gate, signed tag plus GitHub release on G's yes naming 1.5.0) beside Track B (explainer model research on Isambard-AI to a judged build and G's pick, stage caps inside the 20,000 GPU-hour allocation per DEC-002; no model in 1.5.0)
last_checkpoint: a1ccc9b 2026-11-12T14:36:00Z

## Next tasks
- M02-T03 Build the prose training data for the explainer job (codex)
- M02-T06 Re-express the clean held-out inputs in the collected form, or fix per-state scoring (codex)

## Blockers
- none
- Window: no claude-N worker open at 16:00 GMT on 12 Nov for about ten minutes (clean-dev reprovisions the profiles); new claude-N dispatches end by 15:55 or start after its "reprovision done". Send "claude-N quiet" to clean-dev when none is open.
- Host order (G's team-manager chat, 12 Nov, until WGEX says its lab refresh is merged): start a job that takes a heavy slot only while `hostload.sh status` shows one slot held by label M03-T13, or, while WGEX is paused for the clean-dev window, only if both slots are free at that moment. Applies to the M04-T03 executing check and merge, and to M02-T06.

## Pending G decisions
- M04-T03 is stopped (DEC-023): on head 1f0348d the Codex 2 re-check says changes-required (the key-read race is still open through `run_files.py`, a file the task may not touch; keyless runs with a missing run id share a memory key), the Opus privacy re-check approves and rates both advisory. Choice: one more bounded author run that closes the whole class, with `run_files.py` allowed, then both re-checks and the executing check (recommended); or wait. Detail: .plan/work/REV-M04-T03/result.md.
- CSV design (DEC-021): on keyless runs the temporary-key notice is one extra non-finding row in the findings CSV; G may reverse before 1.5.0. Not urgent: whether the kit README's connection check should prove a browser sign-in (DEC-014).

## Re-baselines
- from 100% (plan v3 closed at 1.4.0) to 4% (plan v4 scope and weights, DEC-001, approved by G on 11 Nov 2026)
- from 13% to 12% (plan amendment 1: M00-T06 and one new M00 item for the as-of date, DEC-005)

- from 36% to 35% (plan amendment 2: milestone M07 at weight 12, M02-T06, new weights; DEC-018)

## Quota snapshot
<!-- quota:begin -->
claude 56% orchestrator
claude-1 57% ok
claude-2 49% shared
claude-3 50% ok
claude-4 0% ok
claude-5 72% ok
codex 91% hot
codex2 85% hot
<!-- quota:end -->
