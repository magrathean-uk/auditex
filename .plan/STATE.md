# STATE
<!-- The only file read at every session start. Max 40 lines. Rewritten by checkpoint.sh and by small edits. -->
overall: 11% (was 4%)
milestone: M00-foundation 78%
plan_version: v3
release_scope: 1.4.0 from plan v2's BACKLOG Next items - lint-enforced gates, byte-reproducible dist (wheel and sdist), make acceptance with the full v3.9.1 replay at each milestone close, model layer retired via the deletion gate with unchanged output, dead-code and bootstrap-copy cleanup with the forwarder proof, DEC-011 scanner follow-ups, D5-v2 masking of everyone in the run's directory records, signed v1.4.0 tag plus GitHub release with wheel and sdist (no PyPI) on G's yes
last_checkpoint: ce4feb3 2026-11-09T11:53:00Z

## Next tasks
- M00-T03 Re-run the gate chain on main after the M00 merges (luna)

## Blockers
- none

## Pending G decisions
- G's yes naming 1.4.0 at publication (D9). Deletion gates (DEC-005, DEC-006) and the D5 design are approved.

## Notes
- M03-T02 merges before M02-T03 is cut, so the shared test and doc files serialise M03 first (deviation from the M03 precondition, same effect).

## Re-baselines
- from 100% (plan v2, 1.3.0 published at v1.3.0 on d9f050f) to 4% (plan v3 DoD, DEC-001)

## Quota snapshot
<!-- quota:begin -->
claude 88% orchestrator
claude-1 79% ok
claude-2 27% shared
claude-3 80% ok
claude-4 75% ok
claude-5 6% ok
codex - unknown:collector
codex2 33% ok
<!-- quota:end -->
