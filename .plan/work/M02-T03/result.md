## RESULT M02-T03
status: done
summary: The 12 round-2 teacher jobs were still pending on the normal queue at 17:26 GMT. The interactive reservation accepts only one job per user at a time (1 running and 1 submitted), so one job replaces all 12.
  First I held the 12 jobs. Then I submitted 8357551 to the interactive reservation. It started at 17:26:26 GMT and runs the unchanged teacher.sbatch 12 times in sequence: fill5a, then fill5b, then rest2 shards 0/10 to 9/10. Each run uses the settings of the job it replaces and writes the same raw file.
  At 17:29 GMT all 24 fill5a candidates were on disk, so I cancelled the 12 held jobs. None of them had started, so no case runs twice and none is lost.
  8357551 is left running, as this round asked; at round 1's speed it should take about 2 hours. Nothing else of mine is on the system. I did not collect, and kit data/explainer, data/splits.json and runs/usage are unchanged.
  A later worker must add 8357551 to plans/inflight-jobs.json before running collect.sh (see risks).
changes: kit runbook/README.md section 12 (status paragraph plus a new subsection, "Round 2 on the interactive reservation"); project store runs/m02t03/round2-interactive.sbatch (the wrapper job; a copy is .plan/work/M02-T03/round2-interactive.sbatch); .plan/work/M02-T03/{notes.md (Round 3), progress.md}. No repository edits.
verification: brief verify (grep, kit-check checks, twins against M02-T02, collected against M02-T06) against a scratch copy of this block's Findings under $TMPDIR/M02-T03-r3: pass
verification: kit-check usage on the same scratch result: pass (4.7878 GPU-hours, 36 jobs); data/explainer SHA256SUMS: pass, and no kit data or usage file has changed since round 2; the system's copies of the teacher scripts, configs and case files have the same sha256 as the kit's
risks: collect.sh takes its job ids from plans/inflight-jobs.json, which lists only the 12 cancelled ids. Run as it is, it would not wait for 8357551, so it would copy partial raw files. It would also leave 8357551 out of accounting-prose-run3.psv and jobs.json, and kit-check usage would then fail to reconcile. The collecting worker must add 8357551 there first: collect.sh also needs a change to skip an entry with no raw file. The alternative is to wait for 8357551 to end and add its accounting export and jobs.json entry by hand. The recipe is in runbook section 12.
risks: 8357551 holds this account's only interactive slot for about 2 hours, so no other task can use the interactive reservation until it ends. Its time limit is 6 hours. If it times out, the raw files keep what was written, and resubmitting the same wrapper resumes where it stopped.
risks: The 4 MS.EXO.2.2v3 not_met refill cases may still fail check a, as 21 of the 23 candidates on that cell's only generated case did.
questions_for_g: none
### Findings
prose-data: pass
checks-sha256: 3241cf2ccd799aa49496417c3c484ba807daad106df40d22cd561d3d1f0be44e
prose-rows-train: 744
prose-rows-validation: 41
prose-rows-by-verdict: met 241, not_met 253, not_assessed 267, not_applicable 24
prose-cases: 3771 (3767 plus 4 refill); 785 rows, 196 dropped by checks, 2790 queued (rest2 2786, fill5 4), 0 removed by the held-out filter
prose-sealed-twins-dropped: 9
prose-collected-twins-dropped: 0
prose-collected-conflicts-dropped: 0
prose-heldout-filter: 0 of 3771 cases removed at placing (sealed 0, collected 0, conflicts 0); the 9 sealed twins were dropped at build
prose-cells-train: 313/314
prose-cells-missing: MS.EXO.2.2v3 not_met (5 train cases: 1 generated with 23 candidates, each failing at least one of a 21, S 15, m 8, e 4, e3 1; 4 constructed refill cases queued, not yet generated)
prose-candidate-failures: S 119, a 107, b 68, c 34, d 3, e 76, e2 2, e3 28, m 122, p 7, v 30, parse 5
prose-case-drops-by-check: S 52, a 66, b 48, c 26, d 2, e 45, e2 2, e3 13, m 28, p 3, v 24, parse 4
splits-roles: explainer/train.jsonl explainer-train, explainer/validation.jsonl explainer-validation, 41 other files other
teacher: mistralai/Mistral-Small-4-119B-2603@a11f36bebf709121056b1dbcc943d1c6afbe494d (bf16 conversion manifest 7a9eb6d2...0f7d)
jobs-queued: rest2 shards 0/10-9/10 8355767-8355776 (2786 cases, one greedy candidate each); fill5a 8355826 and fill5b 8355827 (4 refill cases, 6 candidates each)
jobs-round2: 8357551 running on the interactive reservation (fill5a, fill5b, rest2 shards 0/10-9/10 in sequence, the same 2790 cases and raw files); 8355767-8355776 and 8355826-8355827 cancelled before start (replaced by 8357551)
gpu-hours: prose 4.79
gpu-hours-so-far: 4.79 counted (rounds 1-2); the 12 cancelled jobs 0; 8357551 running since 17:26 GMT, not yet exported (expected about 8)
