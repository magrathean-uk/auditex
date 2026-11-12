## RESULT M02-T03
status: blocked
summary: 785 teacher-written rows pass every frozen check (744 train, 41 validation; tree 3241cf2c...). Train covers 313 of 314 template cells; MS.EXO.2.2v3 not_met has no passing candidate.
summary: Blocked on two questions. (1) The kit's held-out code requires data/splits.json once kit data/ holds a file, and that file is outside this task's files line. (2) With data/splits.json listing the rows as train and validation, M02-T02's twins check fails soundness (82 evidence keys with two verdicts) in a scratch kit copy.
summary: So the rows are staged in .plan/work/M02-T03/stage/ and nothing is under kit data/. Teacher Mistral-Small-4-119B-2603 @ a11f36be..., converted once to bf16 because FP8 needs the kernels package the environment lacks.
summary: No normal-queue node started in 90 minutes, so all generation ran on the interactive slot. 2,786 cases were not generated. No job is left on the system.
changes: kit runs/usage/M02-T03/{jobs.json,accounting-prose.psv,accounting-prose-run2.psv,SHA256SUMS}; kit runbook/README.md section 12 (named by the brief); staged, not placed: .plan/work/M02-T03/stage/data/explainer/** and stage/data/splits.json; .plan/work/M02-T03/{notes.md,progress.md}
verification: brief verify (grep plus kit-check checks) on a scratch kit copy and a scratch result under $TMPDIR with the lines below plus prose-data: pass: PASS; not run on the real kit (data not placed)
verification: kit-check usage on the real kit, scratch result: PASS (4.7878 GPU-hours, 36 jobs); kit-check twins for M02-T02: real kit PASS, scratch kit with the data placed FAIL (soundness); kit-check checks for M02-T04 on the real kit: PASS
risks: Once the rows are listed as train and validation, the twin definition is unsound on 1.4.0 rule verdicts: 6 conflicting keys among the prose rows and about 76 against oracle labels. This is the same form mismatch as DEC-013 and M02-T06.
risks: Training targets copy most remediation steps from the template, so the fuller text is mainly in the explanation. Coverage-first sampling (main1 shard 0, gap1, fix passes) means only 785 of 3,767 cases are rows.
risks: About 50 GB of stale partial download files remain in the project-store hub cache from the dropped login-node fetch; they go through the deletion gate.
questions_for_g: (orchestrator) May M02-T03 write kit data/splits.json? If yes, with which roles for data/explainer/train.jsonl and validation.jsonl? Listed as train and validation, the M02-T02 twins soundness gate fails. Listed under another role, the rows are not compared, and twin-freeness rests on build_cases.py, which dropped 9 held-out twins. Or should checks/twins.py change? Collecting commands are in .plan/work/M02-T03/notes.md.
### Findings
checks-sha256: 3241cf2ccd799aa49496417c3c484ba807daad106df40d22cd561d3d1f0be44e
prose-rows-train: 744
prose-rows-validation: 41
prose-rows-by-verdict: met 241, not_met 253, not_assessed 267, not_applicable 24
prose-cells-train: 313/314 (missing MS.EXO.2.2v3 not_met)
prose-cases: 3767 built (3450 train, 317 validation by twin group), 1,103 generated, 785 kept, 196 dropped, 2786 not generated
prose-heldout-twins-dropped: 9 (at build, M02-T01 definition)
prose-candidates: 1139 (fix passes included); verdict key removed 2 (smoke), evidence_refs filled from template 68
prose-candidate-failures: S 119, a 107, b 68, c 34, d 3, e 76, e2 2, e3 28, m 122, p 7, v 30, parse 5
prose-case-drops-by-check: S 52, a 66, b 48, c 26, d 2, e 45, e2 2, e3 13, m 28, p 3, v 24, parse 4
teacher: mistralai/Mistral-Small-4-119B-2603@a11f36bebf709121056b1dbcc943d1c6afbe494d (bf16 conversion manifest 7a9eb6d2...0f7d)
jobs: generating 8350848, 8351283, 8351800, 8351943, 8352009, 8352192; CPU 8350173, 8350547; all 36 in kit runs/usage/M02-T03/jobs.json
gpu-hours: prose 4.79
