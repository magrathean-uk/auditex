## RESULT PLAN-v3
status: done
summary: Removed the ledger awk provider predicate from ARCHITECTURE.md and the M01, M02, M04, M05 and M06 Review items. The full anchored 40-character SHA checks are unchanged.
ARCHITECTURE.md now has a "Provider binding" bullet that describes the orchestrator check at milestone close, and each of the five affected Review items repeats it.
The check: the sha in the squash commit's "Plan-Review: REV-<task> approve <sha>" trailer prefixes the full 40-character reviewed SHA in the review result. The review's dispatch record names a launcher of the other vendor from the author's.
Commit 3aa4e9647d88e04ae3ceb69e60f31a959873d261. Nothing ticked, no weight or DoD-count change.
changes: .plan/ARCHITECTURE.md, .plan/milestones/M01-build-and-acceptance.md, M02-model-layer-retirement.md, M04-boundary-scanners.md, M05-d5-name-masking.md, M06-release-1-4-0.md
verification: percent.py --check on the final commit: pass (overall 4%, unchanged). git status clean after the commit.
risks: The provider check is now manual, so the orchestrator must apply it at each milestone close. The trailer sha is still matched as a full 40 characters in the shell predicate, not as a prefix.
questions_for_g: none
