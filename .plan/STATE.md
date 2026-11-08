# STATE
<!-- The only file read at every session start. Max 40 lines. Rewritten by checkpoint.sh and by small edits. -->
overall: 86% (was 84%)
milestone: M03-release-1-3-0 55%
plan_version: v2
release_scope: 1.3.0 from the accepted line (main contains origin/main 82d7ca5) - reproducible local gates, test-proven transport, read and secret boundaries, accurate docs, release notes with the D6 limit, signed v1.3.0 tag plus GitHub release with wheel and sdist (no PyPI) on G's yes
last_checkpoint: 3742f27 2026-11-08T22:07:24Z

## Next tasks
- M03-T04 Pre-publication release gate validation (astra)
- M03-T05 Tag and publish 1.3.0 after G's yes (orchestrator)
- M03-T06 Verify the published release (luna)

## Blockers
- none

## Pending G decisions
- Legal notice: G approved the exact text on 8 Nov 2026 (DEC-005); M02-T07 applies it after M02-T05 merges.
- Later, at release: the separate yes naming 1.3.0 for the `v1.3.0` tag and GitHub release (D9; form fixed by DEC-001).

## Re-baselines
- from 0% (plan v1, checkpoint de3a25d) to 9% (plan v2 DoD, DEC-001, approved by G)
- from 84% to 86% (DEC-017: the acceptance item counts as met with the full v3.9.1 replay waived by G)

## Quota snapshot
<!-- quota:begin -->
claude 86% orchestrator
claude-1 69% ok
claude-2 11% shared
claude-3 - unknown:collector
claude-4 57% ok
claude-5 68% ok
codex 61% ok
codex2 13% ok
<!-- quota:end -->
