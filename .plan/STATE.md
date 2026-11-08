# STATE
<!-- The only file read at every session start. Max 40 lines. Rewritten by checkpoint.sh and by small edits. -->
overall: 70% (was 66%)
milestone: M03-release-1-3-0 0%
plan_version: v2
release_scope: 1.3.0 from the accepted line (main contains origin/main 82d7ca5) - reproducible local gates, test-proven transport, read and secret boundaries, accurate docs, release notes with the D6 limit, signed v1.3.0 tag plus GitHub release with wheel and sdist (no PyPI) on G's yes
last_checkpoint: 670782c 2026-11-08T17:08:15Z

## Next tasks
- M03-T01 Write the 1.3.0 release notes and bump the version (terra)
- M03-T02 Run the acceptance suites on the release commit (luna)
- M03-T03 Build, smoke-test and hash the release artefacts (luna)

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
claude-1 63% ok
claude-2 5% shared
claude-3 71% ok
claude-4 51% ok
claude-5 63% ok
codex 55% ok
codex2 10% ok
<!-- quota:end -->
