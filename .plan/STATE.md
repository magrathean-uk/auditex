# STATE
<!-- The only file read at every session start. Max 40 lines. Rewritten by checkpoint.sh and by small edits. -->
overall: 4%
milestone: M00-foundation 44%
plan_version: v3
release_scope: 1.4.0 from plan v2's BACKLOG Next items - lint-enforced gates, byte-reproducible dist (wheel and sdist), make acceptance with the full v3.9.1 replay at each milestone close, model layer retired via the deletion gate with unchanged output, dead-code and bootstrap-copy cleanup with the forwarder proof, DEC-011 scanner follow-ups, D5-v2 masking of everyone in the run's directory records, signed v1.4.0 tag plus GitHub release with wheel and sdist (no PyPI) on G's yes
last_checkpoint: e9d4214 2026-11-09T08:25:09Z

## Next tasks
- M00-T01 Run the pinned Ruff check in make lint and clear its findings (codex)
- M00-T02 Fix the pytest norecursedirs and taint-scan prune hygiene (codex)
- M00-T03 Re-run the gate chain on main after the M00 merges (luna)

## Blockers
- none

## Pending G decisions
- Deletion gates: the exact M02 removal list (M02-T01) and the M03 cleanup list with the bootstrap copies (M03-T01), when delivered.
- D5 design approval (M05-T01); scope already answered: everyone in the run's own directory records.
- G's yes naming 1.4.0 at publication (D9).

## Re-baselines
- from 100% (plan v2, 1.3.0 published at v1.3.0 on d9f050f) to 4% (plan v3 DoD, DEC-001)

## Quota snapshot
<!-- quota:begin -->
claude 87% orchestrator
claude-1 76% ok
claude-2 22% shared
claude-3 76% ok
claude-4 70% ok
claude-5 83% ok
codex - unknown:collector
codex2 27% ok
<!-- quota:end -->
