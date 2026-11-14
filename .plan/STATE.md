# STATE
<!-- The only file read at every session start. Max 40 lines. Rewritten by checkpoint.sh and by small edits. -->
overall: 69% (was 70%)
milestone: M03-explainer-training 20%
plan_version: v4
release_scope: 1.5.0 (wider Ruff set, contract-test and gate-doc fixes, keyed per-run D5 pseudonyms plus middle initials and titles, v3 DEC-008/009 scanner follow-ups, review follow-ups, microsoft-skills deletion gate, signed tag plus GitHub release on G's yes naming 1.5.0) beside Track B (explainer model research on Isambard-AI to a judged build and G's pick, stage caps inside the 20,000 GPU-hour allocation per DEC-002; no model in 1.5.0)
last_checkpoint: 45d4836 2026-11-14T15:50:40Z

## Next tasks
- M03-T02 Train three seeds of the chosen base on data v2 (terra)
- M03-T03 Build, hash and judge the final explainer build (terra)
- M03-T04 Write the recommendation and the product-integration options (sol)

## Blockers
- Host: the WGEX hold is over (DEC-069; sitting stopped at 2d); one heavy slot through hostload.sh, PLAN_LOAD_MAX=12.
- Track A: 1.5.0 is RELEASED and verified (DEC-052; M06 complete): tag v1.5.0 on a1c6b5e; https://github.com/magrathean-uk/auditex/releases/tag/v1.5.0 (wheel 81ea5c2f..., sdist 959e825f...). Track A reopens only for M08 collection completeness (DEC-059; amendment 5 merged).
- Track B: stopped and on hold (DEC-053, G on 14 Nov: "master data collection etc first ... talk about training AFTER"). The pilot failed (M03-T06: 18 wins of 190, 139 needed; 5.57 GPU-hours). Nothing in M03 moves; amendment 4 (parked case) stays unmerged at bf19a3f. Training is discussed again after phase D. GPU-hours used: about 306 of 20,000.

## Pending G decisions
- Lead reports to the manager chat (DEC-073); Codex 1 unlimited (DEC-076); product code authored on Claude seats, Codex reviews (DEC-077).
- M07 7s: confirmed, frozen dt-r7s-ro 6dae564ece2c (Codex ship). M07-T20 full kit suite queued in the heavy slot (kit 7s full-1-job). Then T21 hand-over and phase D on G's sign-in.
- M08: A1 merged 45d4836; T08 0a8d8e8; T10 3f7f8f5 (main pushed). B scripts frozen 96aee184809c, Codex and Opus ship: Power BI run waits on G's Fabric sign-in. Running: T07 (sol), A2 T02 (sol). Next: T09 after T07; T04 after T07.

## Re-baselines
- from 100% (plan v3 closed at 1.4.0) to 4% (plan v4 scope and weights, DEC-001, approved by G on 11 Nov 2026)
- 13% to 12% (amendment 1, DEC-005); 36% to 35% (amendment 2: M07 at weight 12, M02-T06; DEC-018)
- 53% to 52% (amendment 3, DEC-037); 63% to 62% (M04-T06 added, DEC-045); 64% to 65% (M04-T06 stopped, DEC-048)
- 84% to 70% (amendment 5: M08 at weight 14, others scaled; DEC-059, G via manager; fbce88f); 70% to 69% (amendment 6: round 7s and the Fabric app in M07; DEC-054, DEC-066; 6ddef18)

## Quota snapshot
<!-- quota:begin -->
claude 65% orchestrator
claude-1 76% ok
claude-2 51% shared
claude-3 72% ok
claude-4 49% ok
claude-5 79% ok
codex 1% ok
codex2 91% hot
<!-- quota:end -->
