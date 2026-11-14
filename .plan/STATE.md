# STATE
<!-- The only file read at every session start. Max 40 lines. Rewritten by checkpoint.sh and by small edits. -->
overall: 84% (was 82%)
milestone: M03-explainer-training 20%
plan_version: v4
release_scope: 1.5.0 (wider Ruff set, contract-test and gate-doc fixes, keyed per-run D5 pseudonyms plus middle initials and titles, v3 DEC-008/009 scanner follow-ups, review follow-ups, microsoft-skills deletion gate, signed tag plus GitHub release on G's yes naming 1.5.0) beside Track B (explainer model research on Isambard-AI to a judged build and G's pick, stage caps inside the 20,000 GPU-hour allocation per DEC-002; no model in 1.5.0)
last_checkpoint: fee27ad 2026-11-14T09:26:13Z

## Next tasks
- M03-T02 Train three seeds of the chosen base on data v2 (terra)
- M03-T03 Build, hash and judge the final explainer build (terra)
- M03-T04 Write the recommendation and the product-integration options (sol)

## Blockers
- Host: while G's WGEX sitting is active (records/wgex/sitting-M04-rc3-state.json paused false, stopped null) no heavy job and no heavy-slot waiter (manager); then one heavy slot through hostload.sh, PLAN_LOAD_MAX=12.
- Track A: 1.5.0 is RELEASED and verified (DEC-052; M06 complete): tag v1.5.0 on a1c6b5e; https://github.com/magrathean-uk/auditex/releases/tag/v1.5.0 (wheel 81ea5c2f..., sdist 959e825f...). No new Track A or B work (manager).
- Track B: stopped and on hold (DEC-053, G on 14 Nov: "master data collection etc first ... talk about training AFTER"). The pilot failed (M03-T06: 18 wins of 190, 139 needed; 5.57 GPU-hours). Nothing in M03 moves; amendment 4 (parked case) stays unmerged at bf19a3f. Training is discussed again after phase D. GPU-hours used: about 306 of 20,000.

## Pending G decisions
- Questions go to the team-manager chat (DEC-036), never to G here; its rulings count as his. Messages only for decisions, blockers, G's hands or eyes, reserved actions, asked-for results.
- Collection completeness (sent to the manager 09:40 GMT, 14 Nov): the first collection answers at most 67 of 102 rows (14 Teams, 5 Security Suite, 16 Power BI and Power Platform not collectable as set up; EXP-m07-teams). Recommended: a milestone A Teams certificate, B Power BI/Platform enablement, C Teams app settings, D compliance session; default: none.
- Phase D (M07): STOPPED at its first look-up, no tenant write: kit fault (a Graph 404 with a null StatusCode is not read as "not found"; dt-live/phaseD/FAULT-7r-notfound.md). Round 7s (DEC-054), ahead of everything: M07-T18 author (sol on claude-4) delivers an un-gated candidate kit/20261111-kit-7s/dt-r7s-cand with CANDIDATE.sha256; send its path to the manager; the tenant chat runs read-only dry runs of every phase D script from it; fold findings in; one gate (both providers, full suite 9 of 9); freeze 7s; new hand-over. M07-T15 held.

## Re-baselines
- from 100% (plan v3 closed at 1.4.0) to 4% (plan v4 scope and weights, DEC-001, approved by G on 11 Nov 2026)
- 13% to 12% (amendment 1, DEC-005); 36% to 35% (amendment 2: M07 at weight 12, M02-T06; DEC-018)
- from 53% to 52% (plan amendment 3: the data round adds two M03 items, the pilot and data v2; DEC-037)
- 63% to 62% (M04-T06 added, DEC-045); 64% to 65% (M04-T06 stopped, DEC-048)

## Quota snapshot
<!-- quota:begin -->
claude 58% orchestrator
claude-1 75% ok
claude-2 50% shared
claude-3 70% ok
claude-4 42% ok
claude-5 77% ok
codex 93% hot
codex2 90% hot
<!-- quota:end -->
