# STATE
<!-- The only file read at every session start. Max 40 lines. Rewritten by checkpoint.sh and by small edits. -->
overall: 100% (was 96%)
milestone: M06-release-1-4-0 100%
plan_version: v3
release_scope: 1.4.0 from plan v2's BACKLOG Next items - lint-enforced gates, byte-reproducible dist (wheel and sdist), make acceptance with the full v3.9.1 replay at each milestone close, model layer retired via the deletion gate with unchanged output, dead-code and bootstrap-copy cleanup with the forwarder proof, DEC-011 scanner follow-ups, D5-v2 masking of everyone in the run's directory records, signed v1.4.0 tag plus GitHub release with wheel and sdist (no PyPI) on G's yes
last_checkpoint: 5171cc2 2026-11-10T09:40:32Z

## Next tasks
- none

## Blockers
- none

## Pending G decisions
- Plan v4 gate (see `.plan/work/PLAN-v4/answers.md`): the scope of the next release; for model re-training on AIRR (Isambard-AI, plentiful hours, ends late January 2027, G logs in) the model's job and how it is judged, and the base-model comparison with Qwen 4; whether the keyed D5 pseudonym scheme (a bundle change) is in scope; priority between the AIRR track and the product release.

## Notes
- 1.4.0 is released (DEC-011): signed tag v1.4.0 on 5843f0b, GitHub release verified (M06-T05). Plan v3 is complete.
- Handover, 10 Nov 2026: the orchestrator role passes to a new session. The passover is in the machine records folder for this project (`PASSOVER.md`, decisions D10 to D13). The next plan starts with `/plan reset`.
- The v3 push gate and DoD helper are in the records folder under `tools/`. Plan v4 reuses task ids: archive the v3 work folders first and use `v4-Mxx` tag names.

## Re-baselines
- from 100% (plan v2, 1.3.0 published at v1.3.0 on d9f050f) to 4% (plan v3 DoD, DEC-001)

## Quota snapshot
<!-- quota:begin -->
claude 94% orchestrator
claude-1 90% hot
claude-2 35% shared
claude-3 89% hot
claude-4 83% ok
claude-5 33% ok
codex 87% hot
codex2 59% ok
<!-- quota:end -->
