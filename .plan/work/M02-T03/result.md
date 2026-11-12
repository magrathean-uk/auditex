## RESULT M02-T03
status: done
summary: Placed: 785 of the 3,767 cases are rows (744 train, 41 validation) in kit/data/explainer, listed in kit/data/splits.json as explainer-train and explainer-validation, every other file other. The full verify passes on the real kit.
  Filtered all 3,771 cases (3,767 plus 4 refill cases) against the sealed and the collected held-out sets, with the twin definition, field reads and conflict rule kit-check collected uses: 0 removed. The build had already dropped 9 sealed twins.
  Cell listed as missing: MS.EXO.2.2v3 not_met. build_cases.py --refill added its 4 constructed not_met vectors (all train); their jobs are queued.
  Submitted to the normal queue first: rest2 (the 2,786 cases not generated in round 1, jobs 8355767-8355776) and fill5a/fill5b (8355826, 8355827). All 12 were still pending at 17:21 GMT: each needs a whole 4-GPU node, and sbatch --test-only estimated a start on 13 Nov in the evening. Left queued, as the brief allows.
  Collecting: once all 12 jobs have ended, kit/data/explainer/collect.sh copies the raw candidates, refilters, rewrites both manifests, saves accounting-prose-run3.psv and adds the jobs to jobs.json. Exact commands are in .plan/work/M02-T03/notes.md and kit runbook section 12, "Round 2".
changes: kit data/explainer/** (rows, split-manifest.json, drops.json, cases.jsonl now 3,771, selection.json, build_cases.py --refill, filter_rows.py held-out filter, make_manifests.py explainer roles, collect.sh, plans/{rest2,fill5}.jsonl, plans/inflight-jobs.json, teacher-config-fill5{a,b}.json, README.md, SHA256SUMS); kit data/splits.json; kit runbook/README.md section 12; project store runs/m02t03/{rest2,fill5}.jsonl and kit/data/explainer/teacher-config-fill5{a,b}.json; .plan/work/M02-T03/{notes.md,progress.md,stage/**}. No repository edits.
verification: brief verify (grep, kit-check checks, twins against M02-T02, collected against M02-T06) on the real kit, against a scratch copy of this block's lines under $TMPDIR/M02-T03/result.md: pass (collected: 2 explainer files compared, collected-explainer-twins 0)
verification: kit-check usage on the same scratch result: pass (4.79 GPU-hours, 36 jobs); data/explainer SHA256SUMS: pass; held-out filter probe: catches 221/221 collected rows, 501/501 sealed rows and 20/20 collected rows given a flipped verdict; collect.sh --dry-run: pass (kit unchanged)
risks: Data stays at 785 rows (21 per cent of cases) until the 12 queued jobs run and are collected. They are not in jobs.json yet, because their accounting can only be exported after they end; collect.sh adds both. They used no GPU-hours. To get rows sooner, the orchestrator could move them to the interactive reservation.
risks: MS.EXO.2.2v3 not_met: on its one generated case, 21 of 23 teacher candidates state another verdict (check a), so the 4 refill cases may fail the same way.
risks: About 50 GB of stale partial download files from round 1 remain in the project-store hub cache; deleting them goes through the deletion gate.
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
gpu-hours: prose 4.79
