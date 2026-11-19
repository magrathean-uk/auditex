# STATE
<!-- The only file read at every session start. Max 40 lines. Rewritten by checkpoint.sh and by small edits. -->
overall: 84% (was 87%)
milestone: M07-dummy-tenant-kit 89%
plan_version: v4
release_scope: 1.7.0 RELEASED 19 Nov (M10 local answer: qwen default, mistral, gemma, small; DEC-113, DEC-119, DEC-120). Next release 1.8.0: M11 fixes and compact model. M11 Auditex model, attack loop and scale testing planned (DEC-115, cap 5,000 GPU-hours).
last_checkpoint: 7d6b8d7 2026-11-16T06:54:48Z

## Next tasks
- M11-T01 done: scale-rules pass, scale pass (4 models x 2,048 tenants, 37.27 GPU-hours).
- M11-T02 round 1 done (result-r1.md: one root, lone UTF-16 surrogate; stop 204 and intent 56 tricks). Fixes worker on `task/M11-T02-attack-fixes-1` (brief fixes-1.md; claude-3 sol). Then one Codex review (evidence/finalise scope), merge, then retrained rounds 2 and 3 on Isambard. Kit `attack/SUBMIT.md`.
- M11-T03 criteria to write after the first clean round; GPU training by 15 Jan 2027 (DEC-127).
- Each Isambard step needs a live sign-in window (G); check `ssh -O check` first.
- M07-T17 lab rollback by 30 Nov (G approved, DEC-126), then G passes `~/Desktop/cancel-lab-trials.md` to Codex.

## Blockers
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
