## RESULT AMEND-5
status: done
summary: Finding 1: the new "Order and file ownership" section is at .plan/milestones/M08-collection-completeness.md:12-15. The C precondition requiring B complete is at :72. Finding 2: the live DoD item is at :29; it requires app-only certificate mode and checks all 35 policy-id rows bound to the run manifest; M08-T06 acceptance updated to match. Finding 3: M08-T03's two open points are at :63, the 14 of 16 cap at :66, files with power_platform.py at :69, the goal at :21 and .plan/master-plan.md:39; the target is 33 of 35. Commit e92dddb.
changes: .plan/milestones/M08-collection-completeness.md, .plan/master-plan.md
verification: percent.py --repo . --check pass (overall 84%); new DoD command on a synthetic result file passes under sh, bash and zsh, and fails on a product gap, the wrong run mode, a foreign manifest, a duplicate row and a design row reported as decided.
risks: B complete means verify passes, the repo change is merged and both providers say ship; G's operator run gates E, not C. A POST change in M08-T03 gets REV/CHK-M08-T03 in acceptance only, not in the DoD review loop.
questions_for_g: none
