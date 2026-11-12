## RESULT M02-T03
status: done
summary: Collected job 8357551. It ended COMPLETED with exit 0, and all 12 of its runs ended with exit 0. Its raw files are complete: no case is missing and no shard failed. No new job was submitted. The prose data grows to 3,005 rows (2,738 train, 267 validation).
  plans/inflight-jobs.json now lists 8357551, which has no raw file of its own, and collect.sh skips such an entry. collect.sh also had a bug: the ssh calls inside its raw loop read the loop's job list, so the first dry run copied only one raw file. Those calls now read /dev/null.
  The held-out filter ran as in round 2 (DEC-026) and removed 0 of 3,771 cases. The 785 round-2 rows are byte-identical and no row was relabelled. 0 cases are left ungenerated.
  MS.EXO.2.2v3 not_met is still the one missing cell: none of the 71 candidates on its 5 cases passes.
  The accounting export for the 12 cancelled jobs and 8357551 is saved. The task total is 13.01 GPU-hours. Nothing of this task is queued or running.
changes: kit data/explainer/{plans/inflight-jobs.json, collect.sh, raw/fill5a-*, raw/fill5b-*, raw/rest2-teacher-raw-{0..9}of10.jsonl, train.jsonl, validation.jsonl, split-manifest.json, drops.json, SHA256SUMS}; kit data/splits.json; kit runs/usage/M02-T03/{accounting-prose-run3.psv, jobs.json, SHA256SUMS}; kit runbook/README.md section 12 (status paragraph, new "Round 3: collecting 8357551"); .plan/work/M02-T03/{notes.md (Round 4), progress.md}. No repository edits.
verification: collect.sh --dry-run then collect.sh: pass, with identical rows from both. The brief's verify (grep, kit-check checks, twins against M02-T02, collected against M02-T06) on the real kit, against a scratch copy of this block at $TMPDIR/M02-T03/result.md: pass
verification: kit-check usage on the same scratch result: pass (13.01 GPU-hours, 49 attempts). DoD checks-sha256 equal to M02-T04's: pass. bash -n collect.sh: pass. The data/explainer SHA256SUMS verifies.
risks: MS.EXO.2.2v3 not_met has no row because check a fails 68 of its 71 candidates. Closing it needs a decision on the prompt or the check; more samples will not do it.
risks: 2,966 of the 3,005 rows are greedy samples from one teacher, and validation has 267 rows.
questions_for_g: none
### Findings
prose-data: pass
checks-sha256: 3241cf2ccd799aa49496417c3c484ba807daad106df40d22cd561d3d1f0be44e
prose-rows-train: 2738
prose-rows-validation: 267
prose-rows-placed: 3005 (role explainer-train 2738, role explainer-validation 267); round 2 had 785, 2220 added (1994 train, 226 validation)
prose-rows-by-verdict: met 894, not_met 981, not_assessed 1042, not_applicable 88
prose-original-cases-as-rows: 3005 of 3767 (the 4 refill cases: 0 rows)
prose-cases: 3771 (3767 plus 4 refill); 3005 rows, 766 dropped by checks, 0 not generated, 0 removed by the held-out filter
prose-sealed-twins-dropped: 9
prose-collected-twins-dropped: 0
prose-collected-conflicts-dropped: 0
prose-heldout-filter: 0 of 3771 cases removed at placing (sealed 0, collected 0, conflicts 0; 501 sealed and 221 collected rows pinned); the 9 sealed twins were dropped at build
prose-cells-train: 313/314
prose-cells-missing: MS.EXO.2.2v3 not_met (5 train cases: 1 fixture and 4 constructed refill; 71 candidates, every one failing: a 68, S 29, e 13, m 13, b 4, e3 2, parse 1)
prose-candidate-failures: S 231, a 343, b 227, c 103, d 14, e 194, e2 6, e3 79, m 165, p 11, v 89, parse 38
prose-case-drops-by-check: S 152, a 259, b 203, c 95, d 13, e 154, e2 6, e3 63, m 66, p 7, v 83, parse 36
prose-kept-by-sample: greedy 2966, sampled 39
splits-roles: explainer/train.jsonl explainer-train, explainer/validation.jsonl explainer-validation, 53 other files other
data-manifest-sha256: data/explainer/SHA256SUMS 5ec3b695a34dcb877a40a0c5bae249cb06a318134a9167d1b078aaa63d4ceaa4
data-splits-sha256: data/splits.json b1cc94b97773f1d59fca4d62eeab2cae4581e84a8fe912a16d5b49902f6003a1
teacher: mistralai/Mistral-Small-4-119B-2603@a11f36bebf709121056b1dbcc943d1c6afbe494d (bf16 conversion manifest 7a9eb6d2...0f7d)
jobs-round2: 8357551 COMPLETED on the interactive reservation (fill5a, fill5b, rest2 0/10-9/10, all exit 0); 8355767-8355776 and 8355826-8355827 cancelled before start
gpu-hours-8357551: 8.22 (scheduler: 7400 s elapsed x gres/gpu=4)
gpu-hours: prose 13.01
usage-exports: runs/usage/M02-T03/accounting-prose.psv, accounting-prose-run2.psv, accounting-prose-run3.psv; jobs.json 49 jobs
