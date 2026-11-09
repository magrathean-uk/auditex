# STATE
<!-- The only file read at every session start. Max 40 lines. Rewritten by checkpoint.sh and by small edits. -->
overall: 61% (was 56%)
milestone: M02-model-layer-retirement 90%
plan_version: v3
release_scope: 1.4.0 from plan v2's BACKLOG Next items - lint-enforced gates, byte-reproducible dist (wheel and sdist), make acceptance with the full v3.9.1 replay at each milestone close, model layer retired via the deletion gate with unchanged output, dead-code and bootstrap-copy cleanup with the forwarder proof, DEC-011 scanner follow-ups, D5-v2 masking of everyone in the run's directory records, signed v1.4.0 tag plus GitHub release with wheel and sdist (no PyPI) on G's yes
last_checkpoint: fe9d1e4 2026-11-09T19:29:20Z

## Next tasks
- none

## Blockers
- none

## Pending G decisions
- D5 design approval (M05 DoD item 1): G answered its scope, group/role and salt questions (DEC-001, DEC-003, DEC-004); the design document itself is not yet approved. Ask with the repaired M05-T03 evidence.
- G's yes naming 1.4.0 at publication (D9). Deletion gates approved (DEC-005, DEC-006).

## Notes
- Merge order for shared files: DEC-007 (M03-T02 and M05-T03 before M02 to M04 tasks, rebase plus full verify).
- D5 (M05-T03 at 215148d) leaves all 43 contract-smoke digests unchanged (checked 9 Nov), so it can merge before or after M02-T04.

## Re-baselines
- from 100% (plan v2, 1.3.0 published at v1.3.0 on d9f050f) to 4% (plan v3 DoD, DEC-001)

## Quota snapshot
<!-- quota:begin -->
claude - orchestrator
claude-1 84% ok
claude-2 28% shared
claude-3 83% ok
claude-4 79% ok
claude-5 15% ok
codex 86% hot
codex2 38% ok
<!-- quota:end -->
