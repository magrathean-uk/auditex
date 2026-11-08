# STATE
<!-- The only file read at every session start. Max 40 lines. Rewritten by checkpoint.sh and by small edits. -->
overall: 41% (was 35%)
milestone: M00-foundation 45%
plan_version: v2
release_scope: 1.3.0 from the accepted line (main contains origin/main 82d7ca5) - reproducible local gates, test-proven transport, read and secret boundaries, accurate docs, release notes with the D6 limit, signed v1.3.0 tag plus GitHub release with wheel and sdist (no PyPI) on G's yes
last_checkpoint: f0ae2a7 2026-11-08T12:05:13Z

## Next tasks
- M00-T01 Re-run the gate suite on main after the foundation merges (luna)
- M00-T03 Add a dependency audit over the base install and every extra (codex)

## Blockers
- none

## Pending G decisions
- Legal notice: G approved the exact text on 8 Nov 2026 (DEC-005); M02-T07 applies it after M02-T05 merges.
- Later, at release: the separate yes naming 1.3.0 for the `v1.3.0` tag and GitHub release (D9; form fixed by DEC-001).

## Re-baselines
- from 0% (plan v1, checkpoint de3a25d) to 9% (plan v2 DoD, DEC-001, approved by G)

## Quota snapshot
<!-- quota:begin -->
claude 84% orchestrator
claude-1 58% ok
claude-2 2% shared
claude-3 69% ok
claude-4 44% ok
claude-5 61% ok
codex 51% ok
codex2 7% ok
<!-- quota:end -->
