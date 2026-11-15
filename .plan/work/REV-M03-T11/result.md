## RESULT REV-M03-T11
status: done
summary: verdict: approve reviewed: c544a069d219
Writer choice follows DEC-102. The eight pilot-3 files are byte-identical. generate.py adds only four-candidate first-passing selection, multi-GPU loading and per-candidate check results; the judge never selects.
kit-check dataround accepts pilot-4 only after pilot 3's recomputed failure, and recomputes the first-passing selection. The usage evidence reconciles: 13.7612 GPU-hours over five jobs, and only training-side rows were used.
Blocks M03-T12: the plan must give the dataround check a scored pilot-4 verifier first (finding 1).
changes: none in the kit or repository; review notes in .plan/work/REV-M03-T11/ (notes.md, evidence.md, progress.md, dataround-tests.log)
verification: pilot-4 and usage SHA256SUMS verify, pass; cmp of the 8 copies against pilot 3, pass; dataround tests (90), pass (heavy slot busy, exit 75; run directly because this focused suite takes under five minutes); kit-check dataround --result .plan/work/M03-T11/result.md, pass (13.7612 recomputed)
risks: full pilot run time (about 340 GPU-hours on one node; see finding 3); medium reasoning effort instead of the publisher default xhigh may cost quality; candidates are seeded per batch (as in pilot 3), so a resharded rerun is not reproducible (the raw rows are kept)
questions_for_g: none
### Findings
Required changes to M03-T11: none. Follow-ups for the lead:
1. Fix the plan before M03-T12 is dispatched. The dataround check's task list (TASKS) stops at M03-T11. Whenever pilot-4 exists, the pilot-4 preparation check runs for every task and refuses any targets, judgements or measures in pilot-4. So M03-T12's verify step cannot pass, and once M03-T12 writes targets the dataround checks for M03-T09, M03-T10 and M03-T11 fail too. M03-T12's file list excludes checks/**. Amend it to add a scored pilot-4 verifier, reviewed by the other vendor.
2. The check path changed. Pilot 4 sends the raw answer after </think> to the frozen checks as strict JSON, where pilot 3 first cleaned it with parse_output. Pilot 4 is stricter, never looser, and generate.py and the verifier agree. M03-T12 must build its targets from kept_target and must not run parse_output again.
3. Run time: the smoke took about 400 s per candidate (batch of 2, about 5 new tokens/s). 190 headroom rows x 4 = 760 candidates, about 84 node-hours, so one 6 h job cannot finish. Shard with --shard i/24 (about 3.5 h each), one raw file per shard. Resubmit any shard that times out (generate.py resumes), then join the raw and selection files. The cost lever is generating all four candidates when sample 0 passed in 5 of 5 rows; the verifier requires all four, so changing that needs a decision.
4. The candidate list leaves out Ling 3.1 Flash 1019 (AA 30, 560B) and MiMo-V2.6-Pro (AA 30, 1T). Neither fits one node, so the choice stands. The Qwen card matches the stated size, licence, effort levels and sampling defaults.
