# STATE
<!-- The only file read at every session start. Max 40 lines. Rewritten by checkpoint.sh and by small edits. -->
overall: 51% (was 49%)
milestone: M02-explainer-data-and-judging 75%
plan_version: v4
release_scope: 1.5.0 (wider Ruff set, contract-test and gate-doc fixes, keyed per-run D5 pseudonyms plus middle initials and titles, v3 DEC-008/009 scanner follow-ups, review follow-ups, microsoft-skills deletion gate, signed tag plus GitHub release on G's yes naming 1.5.0) beside Track B (explainer model research on Isambard-AI to a judged build and G's pick, stage caps inside the 20,000 GPU-hour allocation per DEC-002; no model in 1.5.0)
last_checkpoint: ace5607 2026-11-13T07:27:06Z

## Next tasks
- none

## Blockers
- Host: the WGEX-first order is lifted (G's team-manager chat, 12 Nov, 23:00 GMT). Use the two heavy slots through hostload.sh in the ordinary way and wait while the load is above 12 (PLAN_LOAD_MAX=12).
- M04-T04 (branch at 0adcc49, accepted under DEC-028) waits for REV-M04-T04 by Codex after the reset (14 Nov, 14:28 UTC; give it evidence-3.md and the BACKLOG line), then merges through the records-folder merge wrapper. M04-T05 (branch at 45bb34f, DEC-029) waits for that merge, then a short re-read and a re-check. M05-T04 and M06-T01 wait for both merges. REV-M02-kit and the M05 other-vendor review wait for the same reset.
- M03-T01 round 1 is done (13 Nov): 4 bases pinned (no Qwen 4), 24 seed and judge jobs submitted, about 260 of 1,024 GPU-hours projected, 13.71 used. Its collecting round waits for the jobs (judging takes 4 to 5 hours per job; Qwen3.8-27B was still fetching) and for M03-T05 (explainer score kind, DEC-032; batch-v4-101). G's cluster sign-in of about 06:00 GMT lasts about 12 hours.

## Pending G decisions
- Kit 7r is accepted (both providers ship, suite 9 of 9; manifest 510f26e348fd). The hand-over note is written (records folder, dt-live/HANDOVER-kit-7r.md) but not delivered: the tenant chat is not open. G opens it (or a new tenant chat) and points it at the note; phase D then runs on G's go and sign-ins.
- For G when convenient: whether the kit README's connection check should prove a browser sign-in (DEC-014). Relayed as settled on 13 Nov (DEC-031, reported): rows need not agree on verdict (DEC-026); the CSV notice row stays (DEC-021).

## Re-baselines
- from 100% (plan v3 closed at 1.4.0) to 4% (plan v4 scope and weights, DEC-001, approved by G on 11 Nov 2026)
- from 13% to 12% (plan amendment 1: M00-T06 and one new M00 item for the as-of date, DEC-005)
- from 36% to 35% (plan amendment 2: milestone M07 at weight 12, M02-T06, new weights; DEC-018)

## Quota snapshot
<!-- quota:begin -->
claude 26% orchestrator
claude-1 67% ok
claude-2 49% shared
claude-3 62% ok
claude-4 20% ok
claude-5 75% ok
codex 91% hot
codex2 85% hot
<!-- quota:end -->
