# STATE
<!-- The only file read at every session start. Max 40 lines. Rewritten by checkpoint.sh and by small edits. -->
overall: 53% (was 51%)
milestone: M02-explainer-data-and-judging 75%
plan_version: v4
release_scope: 1.5.0 (wider Ruff set, contract-test and gate-doc fixes, keyed per-run D5 pseudonyms plus middle initials and titles, v3 DEC-008/009 scanner follow-ups, review follow-ups, microsoft-skills deletion gate, signed tag plus GitHub release on G's yes naming 1.5.0) beside Track B (explainer model research on Isambard-AI to a judged build and G's pick, stage caps inside the 20,000 GPU-hour allocation per DEC-002; no model in 1.5.0)
last_checkpoint: ac114b9 2026-11-13T19:31:42Z

## Next tasks
- none

## Blockers
- Host: the WGEX-first order is lifted (G's team-manager chat, 12 Nov, 23:00 GMT). Use the two heavy slots through hostload.sh in the ordinary way and wait while the load is above 12 (PLAN_LOAD_MAX=12).
- M04-T04 (branch at 0adcc49, accepted under DEC-028) waits for REV-M04-T04 by Codex after the reset (14 Nov, 14:28 UTC; give it evidence-3.md and the BACKLOG lines), then merges through the records-folder merge wrapper. M04-T05 (branch at 45bb34f, DEC-029) waits for that merge, then a short re-read and a re-check. M05-T04 and M06-T01 wait for both merges. REV-M02-kit and the M05 other-vendor review wait for the same reset.
- M04-T04 open defect: a name with two middle initials can stay readable when the probe budget runs out (the 41 reviewer probes pass; this case is outside them). It goes in the REV-M04-T04 brief and is fixed, or named as a limit in the privacy reference, before the merge.
- M03 (13 Nov): M03-T01 done, the rule picks Gemma 4 31B (no EU base in the band: Ministral 8B misses the floor on 2 seeds, 14B on 1). Every base ties the template on validation (0.50; the bar needs 0.729, DEC-013). Ceiling probe (M03-T02 round 1, DEC-034, 2.78 GPU-hours): the teacher-written targets themselves score 0.4757 against the template (wins 13, losses 26, ties 174 of 267; 0.47 on the held-out mix), so this training data cannot reach the bar and settings will not help. M03-T02 is partial and held: no sweep job before G's choice. GPU-hours so far: basecmp 235.67 of 1,024, large 2.78 of 2,048.

## Pending G decisions
- Track B after the probe (DEC-035, reported through the team-manager chat on 13 Nov: G answered "A", one data round). First step, no approval needed: a read-only, no-GPU classification of the losing judgements. Then a plan amendment for the data round (task rows, GPU budget row), which needs G's own yes in the orchestrator chat before any job. No large-sweep job before that.
- Kit 7r is accepted (both providers ship, suite 9 of 9; manifest 510f26e348fd). The hand-over note is written (records folder, dt-live/HANDOVER-kit-7r.md) but not delivered: the tenant chat is not open. G opens it (or a new tenant chat) and points it at the note; phase D then runs on G's go and sign-ins.
- For G when convenient: whether the kit README's connection check should prove a browser sign-in (DEC-014). Relayed as settled on 13 Nov (DEC-031, reported): rows need not agree on verdict (DEC-026); the CSV notice row stays (DEC-021).

## Re-baselines
- from 100% (plan v3 closed at 1.4.0) to 4% (plan v4 scope and weights, DEC-001, approved by G on 11 Nov 2026)
- from 13% to 12% (plan amendment 1: M00-T06 and one new M00 item for the as-of date, DEC-005)
- from 36% to 35% (plan amendment 2: milestone M07 at weight 12, M02-T06, new weights; DEC-018)

## Quota snapshot
<!-- quota:begin -->
claude 35% orchestrator
claude-1 68% ok
claude-2 49% shared
claude-3 64% ok
claude-4 23% ok
claude-5 75% ok
codex 91% hot
codex2 85% hot
<!-- quota:end -->
