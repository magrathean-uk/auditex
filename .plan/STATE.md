# STATE
<!-- The only file read at every session start. Max 40 lines. Rewritten by checkpoint.sh and by small edits. -->
overall: 46% (was 42%)
milestone: M02-explainer-data-and-judging 75%
plan_version: v4
release_scope: 1.5.0 (wider Ruff set, contract-test and gate-doc fixes, keyed per-run D5 pseudonyms plus middle initials and titles, v3 DEC-008/009 scanner follow-ups, review follow-ups, microsoft-skills deletion gate, signed tag plus GitHub release on G's yes naming 1.5.0) beside Track B (explainer model research on Isambard-AI to a judged build and G's pick, stage caps inside the 20,000 GPU-hour allocation per DEC-002; no model in 1.5.0)
last_checkpoint: 592db33 2026-11-12T23:36:39Z

## Next tasks
- none

## Blockers
- Host: the WGEX-first order is lifted (G's team-manager chat, 12 Nov, 23:00 GMT). Use the two heavy slots through hostload.sh in the ordinary way and wait while the load is above 12 (PLAN_LOAD_MAX=12).

## Pending G decisions
- Kit 7r is accepted (both providers ship, suite 9 of 9; manifest 510f26e348fd). The hand-over note is written (records folder, dt-live/HANDOVER-kit-7r.md) but not delivered: the tenant chat is not open. G opens it (or a new tenant chat) and points it at the note; phase D then runs on G's go and sign-ins.
- Recommendation no, G to confirm: whether training rows must also agree with each other on verdict (6 keys, 16 rows; DEC-026).
- M03-T01 (base comparison) waits only for G's budget look (caps: basecmp 1,024, large 2,048, build 64 GPU-hours; used so far about 60 of 20,000). The training data is complete: 3,005 rows placed (2,738 train, 267 validation) of 3,767 cases, 766 dropped by the checks, one cell (MS.EXO.2.2v3 not_met) listed missing; verify passes (M02-T03 round 3, 12 Nov).
- For G when convenient: the CSV `pseudonym_notice` row on keyless runs (DEC-021); whether the kit README's connection check should prove a browser sign-in (DEC-014).

## Re-baselines
- from 100% (plan v3 closed at 1.4.0) to 4% (plan v4 scope and weights, DEC-001, approved by G on 11 Nov 2026)
- from 13% to 12% (plan amendment 1: M00-T06 and one new M00 item for the as-of date, DEC-005)
- from 36% to 35% (plan amendment 2: milestone M07 at weight 12, M02-T06, new weights; DEC-018)

## Quota snapshot
<!-- quota:begin -->
claude 20% orchestrator
claude-1 63% ok
claude-2 49% shared
claude-3 57% ok
claude-4 9% ok
claude-5 74% ok
codex 91% hot
codex2 85% hot
<!-- quota:end -->
