# STATE
<!-- The only file read at every session start. Max 40 lines. Rewritten by checkpoint.sh and by small edits. -->
overall: 53% (was 51%)
milestone: M02-explainer-data-and-judging 75%
plan_version: v4
release_scope: 1.5.0 (wider Ruff set, contract-test and gate-doc fixes, keyed per-run D5 pseudonyms plus middle initials and titles, v3 DEC-008/009 scanner follow-ups, review follow-ups, microsoft-skills deletion gate, signed tag plus GitHub release on G's yes naming 1.5.0) beside Track B (explainer model research on Isambard-AI to a judged build and G's pick, stage caps inside the 20,000 GPU-hour allocation per DEC-002; no model in 1.5.0)
last_checkpoint: 29c1384 2026-11-13T19:50:53Z

## Next tasks
- none

## Blockers
- Host: the WGEX-first order is lifted (G's team-manager chat, 12 Nov, 23:00 GMT). Use the two heavy slots through hostload.sh in the ordinary way and wait while the load is above 12 (PLAN_LOAD_MAX=12).
- M04-T04 (branch at 0adcc49, accepted under DEC-028) waits for REV-M04-T04 by Codex after the reset (14 Nov, 14:28 UTC; give it evidence-3.md and the BACKLOG lines), then merges through the records-folder merge wrapper. M04-T05 (branch at 45bb34f, DEC-029) waits for that merge, then a short re-read and a re-check. M05-T04 and M06-T01 wait for both merges. REV-M02-kit and the M05 other-vendor review wait for the same reset.
- M04-T04 open defect: a name with two middle initials can stay readable when the probe budget runs out (the 41 reviewer probes pass; this case is outside them). Ruling (DEC-039): fix it with one more round by a Codex author after REV-M04-T04 has listed everything; it goes in that review's brief.
- M03 (13 Nov): M03-T01 done, the rule picks Gemma 4 31B (no EU base in the band: Ministral 8B misses the floor on 2 seeds, 14B on 1). Every base ties the template on validation (0.50; the bar needs 0.729, DEC-013). Ceiling probe (M03-T02 round 1, DEC-034, 2.78 GPU-hours): the teacher-written targets themselves score 0.4757 against the template (wins 13, losses 26, ties 174 of 267; 0.47 on the held-out mix), so this training data cannot reach the bar and settings will not help. M03-T02 is partial and held: no sweep job before G's choice. GPU-hours so far: basecmp 235.67 of 1,024, large 2.78 of 2,048.

## Pending G decisions
- Questions for G go to the team-manager chat with a recommendation and an evidence path, never to G here (DEC-036, G's own words on 13 Nov); its rulings and relayed words count as his.
- Track B (DEC-035, DEC-037): the classification is done (EXP-m03-losses: the judge is right in 75 of 82 losing judgements; the bar needs about 139 of 190 headroom rows to win, 13 today). Amendment 3 (pilot first, then the round only on a pass) is being drafted as AMEND-3; its path, GPU figure and pass rule go to the manager. No cluster job before its answer.
- Phase D: kit 7r is accepted (manifest 510f26e348fd), the hand-over note is written and not delivered. The manager asks G for a slot and opens the tenant chat then; nothing moves there until it says so. DEC-014's README question is settled: no change (DEC-038).

## Re-baselines
- from 100% (plan v3 closed at 1.4.0) to 4% (plan v4 scope and weights, DEC-001, approved by G on 11 Nov 2026)
- from 13% to 12% (plan amendment 1: M00-T06 and one new M00 item for the as-of date, DEC-005)
- from 36% to 35% (plan amendment 2: milestone M07 at weight 12, M02-T06, new weights; DEC-018)

## Quota snapshot
<!-- quota:begin -->
claude 36% orchestrator
claude-1 68% ok
claude-2 49% shared
claude-3 64% ok
claude-4 24% ok
claude-5 75% ok
codex 91% hot
codex2 85% hot
<!-- quota:end -->
