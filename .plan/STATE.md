# STATE
<!-- The only file read at every session start. Max 40 lines. Rewritten by checkpoint.sh and by small edits. -->
overall: 35% (was 36%)
milestone: M02-explainer-data-and-judging 50%
plan_version: v4
release_scope: 1.5.0 (wider Ruff set, contract-test and gate-doc fixes, keyed per-run D5 pseudonyms plus middle initials and titles, v3 DEC-008/009 scanner follow-ups, review follow-ups, microsoft-skills deletion gate, signed tag plus GitHub release on G's yes naming 1.5.0) beside Track B (explainer model research on Isambard-AI to a judged build and G's pick, stage caps inside the 20,000 GPU-hour allocation per DEC-002; no model in 1.5.0)
last_checkpoint: 79bacab 2026-11-12T13:34:53Z

## Next tasks
- M02-T03 Build the prose training data for the explainer job (codex)
- M02-T06 Re-express the clean held-out inputs in the collected form, or fix per-state scoring (codex)

## Blockers
- none
- Window: no claude-N worker open at 16:00 GMT on 12 Nov for about ten minutes (clean-dev reprovisions the profiles); new claude-N dispatches end by 15:55 or start after its "reprovision done". Send "claude-N quiet" to clean-dev when none is open.

## Pending G decisions
- M02-T06 is blocked on a held-out choice (sent to the team-manager chat, 12:40 GMT on 12 Nov): A, score M03 on the 228 of 501 rows that exist in collected form, with one reviewed change to the kit twins check (recommended); or B, keep the sealed 501 and report per verdict state. Detail: .plan/work/M02-T06/result.md.
- CSV design: on keyless runs the temporary-key notice is one extra non-finding row in the findings CSV (DEC-021); G may reverse before 1.5.0.
- Not urgent: whether the kit README's connection check should prove a browser sign-in (kept out of round 7r, DEC-014).

## Re-baselines
- from 100% (plan v3 closed at 1.4.0) to 4% (plan v4 scope and weights, DEC-001, approved by G on 11 Nov 2026)
- from 13% to 12% (plan amendment 1: M00-T06 and one new M00 item for the as-of date, DEC-005)

- from 36% to 35% (plan amendment 2: milestone M07 at weight 12, M02-T06, new weights; DEC-018)

## Quota snapshot
<!-- quota:begin -->
claude 54% orchestrator
claude-1 55% ok
claude-2 49% shared
claude-3 48% ok
claude-4 0% ok
claude-5 71% ok
codex 91% hot
codex2 84% ok
<!-- quota:end -->
