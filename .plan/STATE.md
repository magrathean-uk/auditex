# STATE
<!-- The only file read at every session start. Max 40 lines. Rewritten by checkpoint.sh and by small edits. -->
overall: 15% (was 11%)
milestone: M00-foundation 78%
plan_version: v3
release_scope: 1.4.0 from plan v2's BACKLOG Next items - lint-enforced gates, byte-reproducible dist (wheel and sdist), make acceptance with the full v3.9.1 replay at each milestone close, model layer retired via the deletion gate with unchanged output, dead-code and bootstrap-copy cleanup with the forwarder proof, DEC-011 scanner follow-ups, D5-v2 masking of everyone in the run's directory records, signed v1.4.0 tag plus GitHub release with wheel and sdist (no PyPI) on G's yes
last_checkpoint: 4d5f303 2026-11-09T12:00:22Z

## Next tasks
- M00-T03 Re-run the gate chain on main after the M00 merges (luna)

## Blockers
- none

## Pending G decisions
- D5 design approval (M05 DoD item 1): G answered its scope, group/role and salt questions (DEC-001, DEC-003, DEC-004); the design document itself is not yet approved. Ask with the repaired M05-T03 evidence.
- G's yes naming 1.4.0 at publication (D9). Deletion gates approved (DEC-005, DEC-006).

## Notes
- Merge order for shared files: DEC-007 (M03-T02 and M05-T03 before M02 to M04 tasks, rebase plus full verify).

## Re-baselines
- from 100% (plan v2, 1.3.0 published at v1.3.0 on d9f050f) to 4% (plan v3 DoD, DEC-001)

## Quota snapshot
<!-- quota:begin -->
claude 88% orchestrator
claude-1 79% ok
claude-2 27% shared
claude-3 80% ok
claude-4 75% ok
claude-5 7% ok
codex - unknown:collector
codex2 33% ok
<!-- quota:end -->
