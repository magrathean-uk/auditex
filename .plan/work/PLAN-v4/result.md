## RESULT PLAN-v4
status: done
summary: I applied all three points from amend-2-fix2.md (review result-6) to M02-T06 and the M02 review item, and committed dabe352 on task/PLAN-v4-plan-v4-amend-2. This is a revision round, so I did not redo the reset.
summary: Point 1 is at .plan/milestones/M02-explainer-data-and-judging.md:77, :21 and :81. Point 2 is at :77 and :21. Point 3 is at :81.
summary: Nothing else changed: no weight, status, tick, other task or other milestone. I did not touch STATE.md or DECISIONS.md. current: 35%
changes: .plan/milestones/M02-explainer-data-and-judging.md
verification: percent.py --repo . --check on dabe352: pass (rc 0, 35%). git diff --check: clean.
risks: The task reuses checks/twins.py unchanged. Its measures.json and reproduction.json expectations may not fit the collected-form rows. The reviewer noted this and it is still open.
questions_for_g: none
### Findings
| id | name | weight | DoD items | ticked |
|---|---|---|---|---|
| M00 | foundation | 7 | see file | all (100%) |
| M01 | airr-bring-up | 13 | see file | all (100%) |
| M02 | explainer-data-and-judging | 14 | 8 | 4 (50%) |
| M03 | explainer-training | 15 | see file | 0% |
| M04 | d5-keyed-pseudonyms | 16 | see file | 13% |
| M05 | scanners-and-hygiene | 10 | see file | 17% |
| M06 | release-1-5-0 | 13 | see file | 0% |
| M07 | dummy-tenant-kit | 12 | 8 | 3 (38%) |
- Honest current percentage: 35%, unchanged by this repair.
- Point 1 (medium), M02:77: the collected set now carries heldout/collected/rule-outputs.json ({case_id: verdict}) and heldout/collected/dropped.json ({case_id: {policy, reason}}). checks/collected.py now checks that:
  - the wheel pin equals WHEEL_SHA256 in judging/inputs/build_inputs.py;
  - kept and dropped case ids are disjoint and together equal the M02-T02 heldout.jsonl case ids;
  - each kept row's verdict equals its sealed label by case id.
- Point 1 also names the count keys heldout-kept-<state> and heldout-dropped-<state> for met, not_met, not_applicable and not_assessed. M02:21 now says REV-M02-kit judges every drop reason, and M02:81 lists the two new files.
- Point 2 (low): the Writes line at M02:77 adds every line `kit-check twins --heldout heldout/collected` prints. M02:21 names `kit-check twins --heldout heldout/collected --result .plan/work/M02-T06/result.md`.
- Point 3 (cosmetic): M02:81 has the comma before checks/collected.py.
- Per-point notes: .plan/work/PLAN-v4/notes.md (last section).
