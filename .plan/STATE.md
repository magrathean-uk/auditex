# STATE
<!-- The only file read at every session start. Max 40 lines. Rewritten by checkpoint.sh and by small edits. -->
overall: 9%
milestone: M00-foundation 18%
plan_version: v2
release_scope: 1.3.0 from the accepted line (main contains origin/main 82d7ca5) - reproducible local gates, test-proven transport, read and secret boundaries, accurate docs, release notes with the D6 limit, signed v1.3.0 tag plus GitHub release with wheel and sdist (no PyPI) on G's yes
last_checkpoint: ba4fade 2026-11-08T11:23:47Z

## Next tasks
- M00-T01 Re-run the gate suite on main after the foundation merges (luna)
- M00-T02 Make the release archive and dist build TMPDIR-safe make targets (codex)
- M00-T03 Add a dependency audit over the base install and every extra (codex)

## Blockers
- none

## Pending G decisions
- Legal notice: approve the exact replacement text M02-T06 drafts (DEC-003); M02-T07 then applies it verbatim.
- Later, at release: the separate yes naming 1.3.0 for the `v1.3.0` tag and GitHub release (D9; form fixed by DEC-001).

## Re-baselines
- from 0% (plan v1, checkpoint de3a25d) to 9% (plan v2 DoD, DEC-001, approved by G)

## Quota snapshot
<!-- quota:begin -->
claude 84% orchestrator
claude-1 58% ok
claude-2 0% shared
claude-3 69% ok
claude-4 42% ok
claude-5 59% ok
codex 50% ok
codex2 6% ok
<!-- quota:end -->
