# STATE
<!-- The only file read at every session start. Max 40 lines. Rewritten by checkpoint.sh and by small edits. -->
overall: 33% (was 30%)
milestone: M00-foundation 85%
plan_version: v4
release_scope: 1.5.0 (wider Ruff set, contract-test and gate-doc fixes, keyed per-run D5 pseudonyms plus middle initials and titles, v3 DEC-008/009 scanner follow-ups, review follow-ups, microsoft-skills deletion gate, signed tag plus GitHub release on G's yes naming 1.5.0) beside Track B (explainer model research on Isambard-AI to a judged build and G's pick, stage caps inside the 20,000 GPU-hour allocation per DEC-002; no model in 1.5.0)
last_checkpoint: 2ce9d23 2026-11-11T19:46:54Z

## Next tasks
- M00-T04 Re-run the gate chain on main after the M00 merges (luna)

## Blockers
- none

## Pending G decisions
- For G to confirm or change (logged by the orchestrator, G-level): DEC-003 (kit verifier accepted on a fixed bar after two repair rounds), DEC-007 (the held-out repair changed the twin definition), DEC-009 (v10 reproduction read as a four-run mean, set after run 1 scored 393 against 400), DEC-010 (shared sign-in cut from the kit round). Later: the explainer acceptance bar before any training run.
- For G to decide (M05 deletion gate): eight unused vendored files under tenant-bootstrap/vendor/microsoft-skills (ALL-SKILLS-CATALOG.md, the microsoft-foundry entry, the entra-agent-id entry). Removing them makes line 16 of docs/legal/third-party-notices.md untrue, so removal needs wording from G for that line. Recommendation: keep them; nothing ships or runs from them. List: .plan/work/M05-T05/result.md.

## Re-baselines
- from 100% (plan v3 closed at 1.4.0) to 4% (plan v4 scope and weights, DEC-001, approved by G on 11 Nov 2026)
- from 13% to 12% (plan amendment 1: M00-T06 and one new M00 item for the as-of date, DEC-005)

## Quota snapshot
<!-- quota:begin -->
claude 28% orchestrator
claude-1 41% ok
claude-2 47% shared
claude-3 33% ok
claude-4 86% hot
claude-5 63% ok
codex 91% hot
codex2 81% ok
<!-- quota:end -->
