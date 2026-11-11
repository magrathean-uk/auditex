## RESULT PLAN-v4
status: done
summary: Second revision round on the plan v4 draft. The reset commit 761b4c6 stands from round one; the plan commit is 5efc94a on task/PLAN-v4-plan-v4. current: 4% (as percent.py computes it; M00 50%).
Fixed gaps 5, 6, 7, N1 and N2: exact `bc` budget sums, the M04 digest-strategy file permission set by G's design decision, M06 checks in the candidate worktree, M02-T02 after M01-T03, and per-task `runs/usage/<task-id>/` folders.
Added G's scope-approval rulings: Mistral Small 4 as teacher, no tell-first download lines, and STATE noting that the orchestrator records DEC-001's date and status. Notes: .plan/work/PLAN-v4/notes.md
changes: .plan/master-plan.md, .plan/ARCHITECTURE.md, .plan/DECISIONS.md, .plan/STATE.md, .plan/milestones/M01-airr-bring-up.md, M02-explainer-data-and-judging.md, M03-explainer-training.md, M04-d5-keyed-pseudonyms.md, M06-release-1-5-0.md; notes.md in the work folder
verification: PASS percent.py --repo . --check (4%); PASS budget predicate probes 14/14 in bash, zsh, sh; PASS candidate-worktree probe (make ran at the candidate after a later .plan commit, dirty worktree fails); PASS digest-strategy probe (seed pass, normalise and unknown fail); PASS bash -n on 92 DoD and verify commands; PASS git diff --check; PASS no workstation paths in the plan files
risks: The candidate-worktree predicate depends on CLEAN_DEV_WORK and the main .venv, and it is tested only on a toy repository, not a real release-check. The digest-strategy line relies on the orchestrator writing `- digest-strategy:` into G's M04 design decision. Running a zsh -c probe created a throwaway worktree under the real 4TB worktrees/auditex folder; I removed it with git worktree remove.
questions_for_g: none new; the M04 design gate will carry the key location and the digest strategy (recommendation: a key file in the run folder, seeded in contract-smoke).
### Findings
| id | name | weight | DoD items | ticked |
|---|---|---|---|---|
| M00 | foundation | 8 | 12 | 6 |
| M01 | airr-bring-up | 15 | 8 | 0 |
| M02 | explainer-data-and-judging | 15 | 7 | 0 |
| M03 | explainer-training | 17 | 8 | 0 |
| M04 | d5-keyed-pseudonyms | 18 | 8 | 0 |
| M05 | scanners-and-hygiene | 12 | 6 | 0 |
| M06 | release-1-5-0 | 15 | 10 | 0 |
current: 4% (percent.py). Revision notes: .plan/work/PLAN-v4/notes.md
