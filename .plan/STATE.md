# STATE
<!-- The only file read at every session start. Max 40 lines. Rewritten by checkpoint.sh and by small edits. -->
overall: 84% (was 87%)
milestone: M07-dummy-tenant-kit 89%
plan_version: v4
release_scope: 1.6.0 RELEASED 16 Nov (DEC-122; M08 collection completeness + M09 one Microsoft 365 way, the reader app with a certificate). Next release: M10 local answer (off-the-shelf local model selects checked sentences; DEC-113, DEC-119, DEC-120). M11 Auditex model, attack loop and scale testing planned (DEC-115, cap 5,000 GPU-hours).
last_checkpoint: 7d6b8d7 2026-11-16T06:54:48Z

## Next tasks
- M10-T03 resume the repair round on `task/M10-T03-local-answer` (WIP cd9b225, unreviewed): dispatch with REVIEW=`.plan/work/M10-T03/continue-2.md` (round 3 stopped on 18 Nov before any edit; its progress.md says the WIP already holds all four fixes, only tests, commits and checks are left; FILES and TITLE from `brief-round2.md`, `--rounds-ok`); then REV-M10-T03 (Codex, prior result-1.md) + CHK-M10-T03, merge, full suite.
- M10-T04 acceptance on the test tenants (99% checks, zero contradictions, DEC-114 injection, DEC-120 completeness), docs; CPU-only speed needs the lean prompt.
- M11 after M10: write each task's criteria before dispatch (amendment 13); first GPU job needs G's Isambard sign-in (send the manager the line).
- M07-T17 rollback of the lab tenant: week of 30 Nov, latest 3 Dec, only after the manager passes on G's word (ROLLBACK-PLAN-2026-11-15.md in records dt-live).

## Blockers
- Paused 18 Nov 13:15 GMT on G's order through the manager (DEC-125): nothing running, no worktree but main; start nothing until the manager's restart plan.
- Host: hostload slots are contended by other projects; heavy runs wait or run directly only with lead authorisation.

## Pending G decisions
- Lead reports to the manager chat (DEC-073, DEC-103 manager session); product code on Claude seats, Codex reviews (DEC-077).
- Rollback timing (G's word via manager); Isambard sign-in when M11 GPU work starts.

## Re-baselines
- from 100% (plan v3 closed at 1.4.0) to 4% (plan v4 scope and weights, DEC-001, approved by G on 11 Nov 2026)
- 13% to 12% (amendment 1, DEC-005); 36% to 35% (amendment 2: M07 at weight 12, M02-T06; DEC-018)
- 53% to 52% (amendment 3, DEC-037); 63% to 62% (M04-T06 added, DEC-045); 64% to 65% (M04-T06 stopped, DEC-048)
- 84% to 70% (amendment 5: M08 at weight 14, others scaled; DEC-059, G via manager; fbce88f); 70% to 69% (amendment 6: round 7s and the Fabric app in M07; DEC-054, DEC-066; 6ddef18)
- 99% (weights summing to 132 after M09, M10, M11) to 84% (rescaled to 100, DEC-123)

## Quota snapshot
<!-- quota:begin -->
claude 88% orchestrator
claude-1 82% ok
claude-2 19% shared
claude-3 83% ok
claude-4 74% ok
claude-5 85% hot
codex 37% ok
codex2 29% ok
<!-- quota:end -->
